//! Container enrichment for process events (Phase 2 #2.9).
//!
//! Given a pid, parses `/proc/<pid>/cgroup` (v1 and v2) and best-effort
//! detects the runtime + container id from well-known cgroup path
//! shapes. When the local Docker / containerd socket is reachable, we
//! also look up the container image name via a minimal hand-rolled
//! HTTP/1 GET over a unix-domain socket. Results are cached per
//! (pid, container_id) so a hot exec-spam loop pays the parse cost
//! once per fresh container, not per event.
//!
//! Design notes:
//!   * No external HTTP-over-uds crate — `tokio::net::UnixStream` + a
//!     5-line request/response shape keeps the agent's dependency
//!     surface (and binary size) honest.
//!   * Every fallible step downgrades to `None` rather than bubbling
//!     errors — container telemetry is enrichment, never a hard
//!     requirement for emitting a process event.
//!   * The cache is bounded; coarse eviction kicks in when we exceed
//!     `MAX_CACHE_ENTRIES` so a long-lived agent on a busy
//!     orchestrator host doesn't grow unbounded.
//!
//! ECS shape on the manager side:
//!   container.id            full container id (64-char hex for docker/containerd)
//!   container.image.name    image:tag string (best-effort, may be missing)
//!   container.runtime       lower-snake-case runtime token

use agent_core::proto as p;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const DOCKER_SOCK: &str = "/var/run/docker.sock";
const CONTAINERD_SOCK: &str = "/var/run/containerd/containerd.sock";
const IMAGE_LOOKUP_TIMEOUT: Duration = Duration::from_millis(250);
const CACHE_TTL: Duration = Duration::from_secs(300);
const MAX_CACHE_ENTRIES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerInfo {
    pub id: String,
    pub image: String,
    pub runtime: p::ContainerRuntime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    pid: u32,
    /// Truncated container id (first 16 hex chars) — keeps the key
    /// compact while still distinguishing entries.
    id_short: [u8; 16],
}

struct CacheEntry {
    info: Option<ContainerInfo>,
    inserted: Instant,
}

static CACHE: Mutex<Option<HashMap<CacheKey, CacheEntry>>> = Mutex::new(None);

/// Return container metadata for a pid, or `None` for a bare-metal
/// process. Safe to call from async contexts (the socket read is
/// async, the cgroup parse is sync but trivial).
pub async fn enrich(pid: u32) -> Option<ContainerInfo> {
    let parsed = parse_cgroup_for_pid(pid)?;
    let key = cache_key(pid, &parsed.id);

    if let Some(hit) = cache_lookup(&key) {
        return hit;
    }

    let image = match parsed.runtime {
        p::ContainerRuntime::Docker | p::ContainerRuntime::Podman => {
            fetch_docker_image(&parsed.id).await.unwrap_or_default()
        }
        p::ContainerRuntime::Containerd | p::ContainerRuntime::CriO => {
            fetch_containerd_image(&parsed.id).await.unwrap_or_default()
        }
        p::ContainerRuntime::Unknown => String::new(),
    };

    let info = ContainerInfo {
        id: parsed.id,
        image,
        runtime: parsed.runtime,
    };
    cache_insert(key, Some(info.clone()));
    Some(info)
}

fn cache_key(pid: u32, id: &str) -> CacheKey {
    let mut id_short = [0u8; 16];
    let bytes = id.as_bytes();
    let take = bytes.len().min(16);
    id_short[..take].copy_from_slice(&bytes[..take]);
    CacheKey { pid, id_short }
}

fn cache_lookup(key: &CacheKey) -> Option<Option<ContainerInfo>> {
    let mut guard = CACHE.lock().ok()?;
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(entry) = map.get(key) {
        if entry.inserted.elapsed() <= CACHE_TTL {
            return Some(entry.info.clone());
        }
    }
    None
}

fn cache_insert(key: CacheKey, info: Option<ContainerInfo>) {
    let Ok(mut guard) = CACHE.lock() else { return };
    let map = guard.get_or_insert_with(HashMap::new);
    // Cheap bound: when we hit the ceiling, evict everything older
    // than half the TTL. Avoids needing a full LRU structure for an
    // enrichment cache.
    if map.len() >= MAX_CACHE_ENTRIES {
        let cutoff = Duration::from_secs(CACHE_TTL.as_secs() / 2);
        map.retain(|_, e| e.inserted.elapsed() <= cutoff);
    }
    map.insert(
        key,
        CacheEntry {
            info,
            inserted: Instant::now(),
        },
    );
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedCgroup {
    pub id: String,
    pub runtime: p::ContainerRuntime,
}

fn parse_cgroup_for_pid(pid: u32) -> Option<ParsedCgroup> {
    let path = format!("/proc/{pid}/cgroup");
    let contents = std::fs::read_to_string(&path).ok()?;
    parse_cgroup(&contents)
}

/// Detect runtime + container id from a `/proc/<pid>/cgroup` blob.
/// Public for the integration test fixtures.
pub fn parse_cgroup(contents: &str) -> Option<ParsedCgroup> {
    for line in contents.lines() {
        // Format: `<hierarchy_id>:<controllers>:<cgroup_path>`.
        let path = line.splitn(3, ':').nth(2)?;
        if let Some(parsed) = match_cgroup_path(path) {
            return Some(parsed);
        }
    }
    None
}

fn match_cgroup_path(path: &str) -> Option<ParsedCgroup> {
    // Walk segments from leaf to root — the container id always lives
    // in the deepest segment that matches a runtime pattern.
    for seg in path.rsplit('/') {
        if let Some(id) = strip_prefix_id(seg, "docker-", ".scope") {
            return Some(ParsedCgroup {
                id,
                runtime: p::ContainerRuntime::Docker,
            });
        }
        if let Some(id) = strip_prefix_id(seg, "crio-", ".scope") {
            return Some(ParsedCgroup {
                id,
                runtime: p::ContainerRuntime::CriO,
            });
        }
        if let Some(id) = strip_prefix_id(seg, "cri-containerd-", ".scope") {
            return Some(ParsedCgroup {
                id,
                runtime: p::ContainerRuntime::Containerd,
            });
        }
        if let Some(id) = strip_prefix_id(seg, "containerd-", ".scope") {
            return Some(ParsedCgroup {
                id,
                runtime: p::ContainerRuntime::Containerd,
            });
        }
        if let Some(id) = strip_prefix_id(seg, "libpod-", ".scope") {
            return Some(ParsedCgroup {
                id,
                runtime: p::ContainerRuntime::Podman,
            });
        }
    }

    // Legacy v1 docker path: `/docker/<id>` — typical of older
    // cgroupv1 installs without systemd cgroup naming.
    if let Some(rest) = path.strip_prefix("/docker/") {
        let id = rest.split('/').next()?.to_string();
        if looks_like_container_id(&id) {
            return Some(ParsedCgroup {
                id,
                runtime: p::ContainerRuntime::Docker,
            });
        }
    }

    // Kubernetes: `/kubepods.slice/.../docker-<id>.scope` is already
    // handled by the leaf-walk above; the older
    // `/kubepods/.../<id>` shape needs a separate check because the id
    // sits as a bare segment.
    if path.contains("/kubepods") {
        for seg in path.rsplit('/') {
            if looks_like_container_id(seg) {
                return Some(ParsedCgroup {
                    id: seg.to_string(),
                    // Bare segment can't tell docker vs containerd —
                    // default to containerd which is the modern k8s
                    // shape.
                    runtime: p::ContainerRuntime::Containerd,
                });
            }
        }
    }

    None
}

fn strip_prefix_id(seg: &str, prefix: &str, suffix: &str) -> Option<String> {
    let mid = seg.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if looks_like_container_id(mid) {
        Some(mid.to_string())
    } else {
        None
    }
}

fn looks_like_container_id(s: &str) -> bool {
    // 64-char lowercase hex (docker/containerd default) OR 12-char
    // short form. Anything else we treat as not-a-container to avoid
    // mis-attributing systemd unit names like `cron.service`.
    let len_ok = s.len() == 64 || s.len() == 12;
    len_ok && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// `GET /containers/<id>/json` on the Docker engine API. Returns the
/// resolved image name (e.g. `nginx:1.27.0`). Podman ships a
/// docker-compatible socket so the same call path covers both.
async fn fetch_docker_image(id: &str) -> Option<String> {
    let req = format!(
        "GET /containers/{id}/json HTTP/1.1\r\nHost: docker\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    let body = http_uds_get(DOCKER_SOCK, &req).await?;
    parse_docker_image_field(&body)
}

/// Best-effort containerd lookup. The real containerd API speaks grpc
/// — pulling in a full grpc client just for an image-name fetch isn't
/// worth the binary-size cost. For now we fall through to the docker
/// socket (containerd-shim hosts often expose both) and otherwise
/// return None; the manager UI renders "(image unavailable)" for the
/// container.
async fn fetch_containerd_image(id: &str) -> Option<String> {
    if let Some(img) = fetch_docker_image(id).await {
        return Some(img);
    }
    // Probe the containerd socket so a future agent upgrade can wire
    // in a real grpc client without re-plumbing call sites.
    let _ = UnixStream::connect(CONTAINERD_SOCK).await.ok()?;
    None
}

async fn http_uds_get(socket_path: &str, request: &str) -> Option<String> {
    let conn = tokio::time::timeout(IMAGE_LOOKUP_TIMEOUT, UnixStream::connect(socket_path))
        .await
        .ok()?
        .ok()?;
    let mut stream = conn;
    tokio::time::timeout(IMAGE_LOOKUP_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::with_capacity(8 * 1024);
    tokio::time::timeout(IMAGE_LOOKUP_TIMEOUT, stream.read_to_end(&mut buf))
        .await
        .ok()?
        .ok()?;
    let text = String::from_utf8(buf).ok()?;
    // Strip HTTP headers; body starts after the first blank line.
    let body_start = text.find("\r\n\r\n")? + 4;
    let body = &text[body_start..];
    // Some daemons chunk-encode the response — peel one chunk header
    // off (size in hex + CRLF) before handing back to JSON parsing.
    if let Some(first_newline) = body.find("\r\n") {
        let head = &body[..first_newline];
        if u32::from_str_radix(head.trim(), 16).is_ok() {
            return Some(body[first_newline + 2..].to_string());
        }
    }
    Some(body.to_string())
}

/// Extract `Config.Image` from the Docker engine container JSON.
/// We hand-pick the field rather than pulling in serde_json structs
/// because the Docker response is large and we only care about one
/// path.
fn parse_docker_image_field(body: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    let img = parsed
        .get("Config")
        .and_then(|c| c.get("Image"))
        .and_then(|v| v.as_str())?;
    Some(img.to_string())
}

/// Map a `ContainerRuntime` enum value to its ECS-aligned token
/// (`docker`, `containerd`, `cri_o`, `podman`). Mirrors the Python
/// normaliser so log lines and ECS docs agree. Used by the
/// integration tests and exposed for future log/tracing call sites.
#[allow(dead_code)]
pub fn runtime_token(runtime: p::ContainerRuntime) -> &'static str {
    match runtime {
        p::ContainerRuntime::Docker => "docker",
        p::ContainerRuntime::Containerd => "containerd",
        p::ContainerRuntime::CriO => "cri_o",
        p::ContainerRuntime::Podman => "podman",
        p::ContainerRuntime::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_systemd_scope() {
        let s = "0::/system.slice/docker-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope\n";
        let got = parse_cgroup(s).unwrap();
        assert_eq!(got.runtime, p::ContainerRuntime::Docker);
        assert_eq!(got.id.len(), 64);
    }

    #[test]
    fn parses_legacy_docker_v1() {
        let s = "12:cpu,cpuacct:/docker/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n";
        let got = parse_cgroup(s).unwrap();
        assert_eq!(got.runtime, p::ContainerRuntime::Docker);
    }

    #[test]
    fn parses_crio_kubepods() {
        let s = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/crio-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope\n";
        let got = parse_cgroup(s).unwrap();
        assert_eq!(got.runtime, p::ContainerRuntime::CriO);
    }

    #[test]
    fn parses_podman_libpod_scope() {
        let s = "0::/machine.slice/libpod-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210.scope\n";
        let got = parse_cgroup(s).unwrap();
        assert_eq!(got.runtime, p::ContainerRuntime::Podman);
    }

    #[test]
    fn parses_containerd_systemd_scope() {
        let s = "0::/system.slice/containerd-1111111111111111111111111111111111111111111111111111111111111111.scope\n";
        let got = parse_cgroup(s).unwrap();
        assert_eq!(got.runtime, p::ContainerRuntime::Containerd);
    }

    #[test]
    fn ignores_bare_metal_cgroup() {
        let s = "0::/user.slice/user-1000.slice/session-3.scope\n";
        assert!(parse_cgroup(s).is_none());
    }

    #[test]
    fn rejects_short_non_hex_segments() {
        // systemd `cron.service` isn't a container id.
        let s = "0::/system.slice/cron.service\n";
        assert!(parse_cgroup(s).is_none());
    }

    #[test]
    fn parses_image_field_from_docker_json() {
        let body = r#"{"Id":"abc","Config":{"Image":"nginx:1.27.0"}}"#;
        assert_eq!(
            parse_docker_image_field(body).as_deref(),
            Some("nginx:1.27.0")
        );
    }
}

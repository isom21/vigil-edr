# Agent auto-update protocol

> **Status:** manager-side live (Phase 1 #1.6 / PR #67 — state machine,
> wave rollout, auto-rollback semantics). Agent-side fetch / verify /
> swap is still pending and tracked under M9.6.b. The manifest format
> and signing approach below are stable, so a future agent
> implementation can fill in the fetch path without re-litigating the
> design.

## Goals

1. Operator pushes a new agent build → fleet picks it up automatically,
   in waves, with auto-rollback on failure.
2. No customer ever runs an unsigned binary unknowingly.
3. The update path itself can't be a vector — replay attacks, downgrade
   attacks, and CDN compromise are all surfaced.

## Manifest format

A manifest is a JSON document signed with an Ed25519 key. The key is
generated once during M18 prep; the public key ships embedded in the
agent binary so updates are verifiable without a trust dance.

```json
{
  "version": 1,
  "agent_version": "0.2.0",
  "released_at": "2026-06-01T12:00:00Z",
  "channel": "stable",
  "min_protocol_version": 1,
  "platforms": {
    "linux-x86_64": {
      "url": "https://updates.edr.example/0.2.0/vigil-agent_0.2.0-1_amd64.deb",
      "sha256": "abc...",
      "size": 6800000,
      "format": "deb"
    },
    "linux-aarch64": {
      "url": "...",
      "sha256": "...",
      "size": ...,
      "format": "deb"
    },
    "windows-x86_64": {
      "url": "...",
      "sha256": "...",
      "size": ...,
      "format": "msi"
    }
  },
  "rollout": {
    "phase": "wave_2",
    "max_percent": 50,
    "host_group_filter": null
  },
  "signature": "ed25519-base64-of-sha256-of-the-rest"
}
```

Field semantics:

* `agent_version` — must be a strict-monotonic version bump from the
  agent's currently-installed version. Agent rejects any manifest whose
  version is `<=` current (downgrade protection).
* `released_at` — agent rejects manifests whose `released_at` is more
  than 30 days in the future (clock-skew protection) or 365 days in the
  past (replay-of-old-manifest protection).
* `channel` — one of `stable | canary | dev`. Each agent has a config
  knob `update_channel` (default `stable`). Manager only ships
  manifests of the channel the agent is subscribed to.
* `min_protocol_version` — if `<` the agent's compiled `PROTOCOL_VERSION`,
  the manifest is rejected as "old protocol; upgrade manager first".
* `platforms` — keyed by `<os>-<arch>`. Each entry has download URL +
  SHA-256 + size + native package format. Agent picks its own platform
  string at compile time (`cfg!(target_os) + cfg!(target_arch)`).
* `rollout.max_percent` — fraction of the fleet currently allowed to
  install this version. Manager computes this from the rollout state
  machine (see below) and stamps it into the manifest before serving.
* `host_group_filter` — optional UUID list; if non-null, only hosts in
  one of these groups will install. Used for staged rollouts.
* `signature` — Ed25519 signature over the rest of the document
  (canonical JSON, sorted keys). Public key embedded in the agent
  binary at build time.

## Endpoints

### `GET /api/agent-updates/manifest?platform=linux-x86_64&channel=stable&host_id=<uuid>`

Returns the manifest the calling agent should install (or 304 if
already up-to-date). Response:

* `200 OK` + manifest body — agent should download + verify + install.
* `304 Not Modified` — current version is the right one for this
  channel + host_group.
* `404 Not Found` — no manifest for this platform/channel.

Required headers: `Authorization: Bearer <agent_jwt>` (mTLS cert is the
authoritative identity; the JWT is for manager-internal rate-limiting).

The endpoint computes:
1. Look up the latest published manifest for `(channel, platform)`.
2. Apply rollout: deterministic-hash `host_id` into the [0, 1) range;
   serve manifest only if hash < `max_percent / 100`.
3. Apply group filter: serve only if host is in at least one of
   `host_group_filter`.

Cached aggressively (per-channel-per-platform); rollout updates bust
the cache.

### `POST /api/agent-updates/manifests` (admin)

Operator publishes a new manifest. Body is the unsigned manifest +
which channel to publish to. Manager signs it server-side using the
update-signing key and stores. Future-dated `released_at` is allowed
(staged release).

### `POST /api/agent-updates/rollout/{manifest_id}` (admin)

Advance / pause / abort the rollout state machine for a manifest.
Body: `{phase: "wave_1" | "wave_2" | "stable" | "paused" | "aborted",
max_percent: 1..100, host_group_filter: [...]}`.

### `POST /api/agent-updates/result` (agent)

Agent reports success / failure of an attempted install. Body:
`{manifest_version, status: "installed" | "verify_failed" | "install_failed" | "rollback", error: "..."}`.

Manager uses these reports to decide whether to advance the rollout
or pause it.

## Agent-side flow

1. **Poll**: every `update_check_interval` (default 1h) the agent
   GETs `/api/agent-updates/manifest`. Sleep + retry on 304.
2. **Verify manifest**: Ed25519 over canonical JSON. Reject if signature
   bad OR `agent_version <= current` OR `released_at` outside the
   accepted clock-skew window.
3. **Download**: fetch from `platforms.<plat>.url`. Stream to a
   temp file in the agent's `update_staging_dir`. Cap at `2x` the
   declared size.
4. **Verify download**: SHA-256 of the file == `platforms.<plat>.sha256`.
   Reject if mismatch.
5. **Stage install**: write to a side-by-side install dir
   (`<install_dir>/v<version>/`). Don't touch the running binary yet.
6. **A/B switch**:
   * Linux: update a `current` symlink → new dir. systemctl restart
     vigil-agent.
   * Windows: stop service, rename `agent.exe` → `agent.exe.old`, copy
     new in, start service. (The MSI install path is the alternate;
     the MSI itself runs the symlink-equivalent via `MsiInstallProduct`.)
7. **Health check**: agent waits 60s after restart for
   `agent.identity.using_existing` + first `grpc.rule_sync.received`
   in its journal. If those don't appear, **rollback**: switch
   `current` back, restart again.
8. **Report**: POST `/api/agent-updates/result` with the outcome.

## Operator workflow

```
# Build new release packages.
make agent-linux-deb agent-linux-rpm
.\packaging\windows\make-package.ps1

# Compute SHA-256s + draft a manifest.
sha256sum target/debian/*.deb target/generate-rpm/*.rpm
$ docs/scripts/draft-manifest.py --version 0.2.0 --channel canary > manifest.json

# Publish to manager (manager signs).
curl -X POST https://manager/api/agent-updates/manifests \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d @manifest.json

# Wave the rollout: 5% canary -> 10% -> 50% -> 100%.
curl -X POST https://manager/api/agent-updates/rollout/$ID \
    -d '{"phase":"wave_1","max_percent":5}'
# Watch /api/agent-updates/result for failures, advance:
curl -X POST https://manager/api/agent-updates/rollout/$ID \
    -d '{"phase":"wave_2","max_percent":50}'
```

## What's NOT in scope for M9.6

The scaffolding ships the manifest format + endpoints. Pieces still to
build before this is production-ready:

- Agent-side polling loop + download + verify + stage + swap. Today
  agent code does not call `/api/agent-updates/manifest`.
- Manager rollout state machine + rollout dashboard in the UI.
- Update-signing key generation + embed in agent build (M18 prep).
- Differential / delta updates (full installer for now).
- Update-on-boot vs update-while-running semantics for Windows
  (driver vs agent service vs at-rest binary).

These are tracked as M9.6.b through M9.6.f in the milestone backlog
and slot ahead of M14 observability since update is a precondition
for some of M14's fleet-rollout dashboards.

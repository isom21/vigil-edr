//! Helpers for constructing EndpointEvent protobuf messages.

use crate::proto as p;
use prost_types::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_pb() -> Timestamp {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp {
        seconds: dur.as_secs() as i64,
        nanos: dur.subsec_nanos() as i32,
    }
}

pub fn from_unix_ns(ns: u64) -> Timestamp {
    Timestamp {
        seconds: (ns / 1_000_000_000) as i64,
        nanos: (ns % 1_000_000_000) as i32,
    }
}

/// Build an outbound network_connect EndpointEvent. `source_ip` /
/// `destination_ip` are pre-formatted (dotted-quad for IPv4, RFC 5952 for
/// IPv6) and ports are host byte order.
#[allow(clippy::too_many_arguments)]
pub fn network_connect(
    host_id: &str,
    agent_id: &str,
    agent_version: &str,
    pid: u32,
    transport: &str,
    source_ip: &str,
    source_port: u32,
    destination_ip: &str,
    destination_port: u32,
) -> p::EndpointEvent {
    let now = now_pb();
    p::EndpointEvent {
        event_id: ulid::Ulid::new().to_string(),
        event_created: Some(now),
        event_observed: Some(now),
        kind: p::EventKind::Event as i32,
        category: vec![p::EventCategory::Network as i32],
        action: "network_connect".into(),
        outcome: "success".into(),
        host_id: host_id.into(),
        agent_id: agent_id.into(),
        agent_version: agent_version.into(),
        labels: Default::default(),
        payload: Some(p::endpoint_event::Payload::Network(p::NetworkEvent {
            process: Some(p::ProcessKey {
                pid,
                start_time_ns: 0,
            }),
            transport: transport.into(),
            source_ip: source_ip.into(),
            source_port,
            destination_ip: destination_ip.into(),
            destination_port,
            direction: p::NetworkDirection::Outbound as i32,
            action: p::NetworkAction::Connect as i32,
        })),
    }
}

/// Build a file_opened EndpointEvent. `path` is the absolute kernel
/// path (from `bpf_d_path`); `name` is its basename.
#[allow(clippy::too_many_arguments)]
pub fn file_opened(
    host_id: &str,
    agent_id: &str,
    agent_version: &str,
    pid: u32,
    path: &str,
    name: &str,
    action: p::FileAction,
) -> p::EndpointEvent {
    let now = now_pb();
    p::EndpointEvent {
        event_id: ulid::Ulid::new().to_string(),
        event_created: Some(now),
        event_observed: Some(now),
        kind: p::EventKind::Event as i32,
        category: vec![p::EventCategory::File as i32],
        action: match action {
            p::FileAction::Create => "file_created".into(),
            p::FileAction::Write => "file_written".into(),
            p::FileAction::Delete => "file_deleted".into(),
            p::FileAction::Rename => "file_renamed".into(),
            p::FileAction::Blocked => "file_blocked".into(),
            _ => "file_opened".into(),
        },
        outcome: if action == p::FileAction::Blocked {
            "failure".into()
        } else {
            "success".into()
        },
        host_id: host_id.into(),
        agent_id: agent_id.into(),
        agent_version: agent_version.into(),
        labels: Default::default(),
        payload: Some(p::endpoint_event::Payload::File(p::FileEvent {
            process: Some(p::ProcessKey {
                pid,
                start_time_ns: 0,
            }),
            path: path.into(),
            name: name.into(),
            size: 0,
            hash: None,
            action: action as i32,
            ctime: None,
            mtime: None,
            target_path: String::new(),
        })),
    }
}

/// Build an EndpointEvent for a kernel module load. Reuses the
/// `ImageLoadEvent` payload — the module's name lands in `path`, with
/// the actor (modprobe/insmod/etc.) under `process`.
pub fn kernel_module_loaded(
    host_id: &str,
    agent_id: &str,
    agent_version: &str,
    pid: u32,
    module_name: &str,
) -> p::EndpointEvent {
    let now = now_pb();
    p::EndpointEvent {
        event_id: ulid::Ulid::new().to_string(),
        event_created: Some(now),
        event_observed: Some(now),
        kind: p::EventKind::Event as i32,
        category: vec![p::EventCategory::Process as i32],
        action: "kernel_module_loaded".into(),
        outcome: "success".into(),
        host_id: host_id.into(),
        agent_id: agent_id.into(),
        agent_version: agent_version.into(),
        labels: Default::default(),
        payload: Some(p::endpoint_event::Payload::ImageLoad(p::ImageLoadEvent {
            process: Some(p::ProcessKey {
                pid,
                start_time_ns: 0,
            }),
            path: module_name.into(),
            hash: None,
            base_address: 0,
            size: 0,
            signed: false,
            signer: String::new(),
        })),
    }
}

/// Build an EndpointEvent reporting an agent tamper observation
/// (M12.a binary/config drift, M12.b BPF detachment). Always
/// emitted with kind=ALERT and category=INTRUSION_DETECTION so the
/// manager surfaces it immediately, not buried in routine telemetry.
#[allow(clippy::too_many_arguments)]
pub fn agent_tamper(
    host_id: &str,
    agent_id: &str,
    agent_version: &str,
    kind: p::TamperKind,
    target_path: &str,
    expected_hash: &str,
    actual_hash: &str,
    detail: &str,
) -> p::EndpointEvent {
    let now = now_pb();
    let action = match kind {
        p::TamperKind::BinaryMismatch => "agent_tamper_binary",
        p::TamperKind::ConfigMismatch => "agent_tamper_config",
        p::TamperKind::BpfDetached => "agent_tamper_bpf_detached",
        p::TamperKind::BpfMapMissing => "agent_tamper_bpf_map_missing",
        p::TamperKind::Unspecified => "agent_tamper",
    };
    p::EndpointEvent {
        event_id: ulid::Ulid::new().to_string(),
        event_created: Some(now),
        event_observed: Some(now),
        kind: p::EventKind::Alert as i32,
        category: vec![p::EventCategory::IntrusionDetection as i32],
        action: action.into(),
        outcome: "failure".into(),
        host_id: host_id.into(),
        agent_id: agent_id.into(),
        agent_version: agent_version.into(),
        labels: Default::default(),
        payload: Some(p::endpoint_event::Payload::AgentTamper(
            p::AgentTamperEvent {
                kind: kind as i32,
                target_path: target_path.into(),
                expected_hash: expected_hash.into(),
                actual_hash: actual_hash.into(),
                detail: detail.into(),
            },
        )),
    }
}

/// Build a quarantine_completed EndpointEvent (M20.c). Sent by the
/// agent after a QuarantineFileCmd or ReleaseQuarantineCmd resolves so
/// the manager can mark the quarantined_files row active / released /
/// failed in sync with on-disk state.
#[allow(clippy::too_many_arguments)]
pub fn quarantine_completed(
    host_id: &str,
    agent_id: &str,
    agent_version: &str,
    outcome: p::QuarantineOutcome,
    sha256: &str,
    path: &str,
    size_bytes: u64,
    deleted_original: bool,
) -> p::EndpointEvent {
    let now = now_pb();
    let (action, outcome_str) = match outcome {
        p::QuarantineOutcome::Quarantined => ("quarantine_completed", "success"),
        p::QuarantineOutcome::Released => ("quarantine_released", "success"),
        p::QuarantineOutcome::Failed => ("quarantine_failed", "failure"),
        p::QuarantineOutcome::Unspecified => ("quarantine_unspecified", "unknown"),
    };
    p::EndpointEvent {
        event_id: ulid::Ulid::new().to_string(),
        event_created: Some(now),
        event_observed: Some(now),
        kind: p::EventKind::Event as i32,
        category: vec![p::EventCategory::Process as i32],
        action: action.into(),
        outcome: outcome_str.into(),
        host_id: host_id.into(),
        agent_id: agent_id.into(),
        agent_version: agent_version.into(),
        labels: Default::default(),
        payload: Some(p::endpoint_event::Payload::QuarantineCompleted(
            p::QuarantineCompletedEvent {
                outcome: outcome as i32,
                sha256: sha256.into(),
                path: path.into(),
                size_bytes,
                deleted_original,
            },
        )),
    }
}

/// Phase 2 #2.4: build an authentication EndpointEvent. Used by both
/// the Windows ETW collector (Security-Auditing 4624/4625/4768/4769)
/// and the Linux auditd / sshd tail. Pass empty strings for fields the
/// source can't fill — the manager-side normalizer treats them as
/// absent rather than empty.
#[allow(clippy::too_many_arguments)]
pub fn auth_event(
    host_id: &str,
    agent_id: &str,
    agent_version: &str,
    auth_kind: p::AuthKind,
    result: p::AuthResult,
    user: &str,
    user_domain: &str,
    source_ip: &str,
    target_host: &str,
    target_user: &str,
    logon_type: i32,
    ticket_kind: &str,
    service_name: &str,
    failure_reason: &str,
    event_id_raw: u32,
) -> p::EndpointEvent {
    let now = now_pb();
    let action = match auth_kind {
        p::AuthKind::Logon => "logon",
        p::AuthKind::Logoff => "logoff",
        p::AuthKind::KerberosTgt => "kerberos_tgt",
        p::AuthKind::KerberosTgs => "kerberos_tgs",
        p::AuthKind::NtLogon => "nt_logon",
        p::AuthKind::Unspecified => "auth",
    };
    let outcome = match result {
        p::AuthResult::Success => "success",
        p::AuthResult::Failure => "failure",
        _ => "unknown",
    };
    p::EndpointEvent {
        event_id: ulid::Ulid::new().to_string(),
        event_created: Some(now),
        event_observed: Some(now),
        kind: p::EventKind::Event as i32,
        category: vec![p::EventCategory::Authentication as i32],
        action: action.into(),
        outcome: outcome.into(),
        host_id: host_id.into(),
        agent_id: agent_id.into(),
        agent_version: agent_version.into(),
        labels: Default::default(),
        payload: Some(p::endpoint_event::Payload::Auth(p::AuthEvent {
            auth_kind: auth_kind as i32,
            result: result as i32,
            user: user.into(),
            user_domain: user_domain.into(),
            source_ip: source_ip.into(),
            target_host: target_host.into(),
            target_user: target_user.into(),
            logon_type,
            ticket_kind: ticket_kind.into(),
            service_name: service_name.into(),
            failure_reason: failure_reason.into(),
            event_id_raw,
        })),
    }
}

/// Build a process_create EndpointEvent.
#[allow(clippy::too_many_arguments)]
pub fn process_started(
    host_id: &str,
    agent_id: &str,
    agent_version: &str,
    pid: u32,
    start_time_ns: u64,
    parent_pid: u32,
    parent_start_time_ns: u64,
    executable: &str,
    name: &str,
    command_line: &str,
    user_name: &str,
) -> p::EndpointEvent {
    let now = now_pb();
    p::EndpointEvent {
        event_id: ulid::Ulid::new().to_string(),
        event_created: Some(now),
        event_observed: Some(now),
        kind: p::EventKind::Event as i32,
        category: vec![p::EventCategory::Process as i32],
        action: "process_started".into(),
        outcome: "success".into(),
        host_id: host_id.into(),
        agent_id: agent_id.into(),
        agent_version: agent_version.into(),
        labels: Default::default(),
        payload: Some(p::endpoint_event::Payload::Process(p::ProcessEvent {
            process: Some(p::ProcessKey { pid, start_time_ns }),
            parent: Some(p::ProcessKey {
                pid: parent_pid,
                start_time_ns: parent_start_time_ns,
            }),
            executable: executable.into(),
            name: name.into(),
            // M16.g: scrub command_line for credentials before emit.
            // executable / name are filesystem paths and not generally
            // a secret-leak vector.
            command_line: crate::pii::scrub(command_line),
            args: vec![],
            hash: None,
            user: Some(p::User {
                name: user_name.into(),
                domain: String::new(),
                id: String::new(),
            }),
            integrity: p::IntegrityLevel::Unspecified as i32,
            working_directory: String::new(),
            start: Some(from_unix_ns(start_time_ns)),
            end: None,
            exit_code: 0,
            action: p::ProcessAction::Start as i32,
        })),
    }
}

//! Helpers for constructing EndpointEvent protobuf messages.

use crate::proto as p;
use prost_types::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_pb() -> Timestamp {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
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
        event_created: Some(now.clone()),
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
            process: Some(p::ProcessKey {
                pid,
                start_time_ns,
            }),
            parent: Some(p::ProcessKey {
                pid: parent_pid,
                start_time_ns: parent_start_time_ns,
            }),
            executable: executable.into(),
            name: name.into(),
            command_line: command_line.into(),
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

//! agent-core: cross-platform building blocks for the EDR agent.
//!
//! This crate is OS-agnostic. All OS-specific telemetry collection lives in
//! `agent-windows` and `agent-linux`, which depend on this crate.

pub mod proto {
    //! Generated protobuf bindings from `proto/edr/v1/*.proto`.
    tonic::include_proto!("edr.v1");
}

pub mod client;
pub mod config;
pub mod enroll;
pub mod event;
pub mod identity;
pub mod integrity;
pub mod jobs;
pub mod jobs_acquire;
pub mod jobs_diagnostic;
pub mod jobs_handlers;
pub mod jobs_hunt;
pub mod jobs_runtime;
pub mod jobs_sweep;
pub mod pii;
pub mod scanner;
pub mod spool;
pub mod terminal;

pub use anyhow::{Error, Result};

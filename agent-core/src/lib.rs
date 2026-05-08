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
pub mod scanner;
pub mod spool;

pub use anyhow::{Error, Result};

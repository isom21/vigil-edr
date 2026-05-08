//! gRPC client to the manager. M0 stub — wired up in M2.

use crate::Result;

pub struct ManagerClient;

impl ManagerClient {
    pub async fn connect(_endpoint: &str) -> Result<Self> {
        unimplemented!("M2: implement mTLS dial + HostStream")
    }
}

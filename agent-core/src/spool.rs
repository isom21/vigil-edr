//! Disk-backed event spool. Used when the manager is unreachable.
//! M2 will implement a sled-backed ring buffer with byte cap.

use crate::Result;

pub struct EventSpool;

impl EventSpool {
    pub fn open(_dir: &std::path::Path, _max_bytes: u64) -> Result<Self> {
        unimplemented!("M2: implement disk-backed spool")
    }
}

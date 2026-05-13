//! Wire-format helpers shared between the Windows driver IPC code
//! (`driver.rs`) and unit tests that need to run on Linux CI.
//!
//! Anything in this module must build on every host the workspace
//! targets — no `windows-rs`, no `cfg(windows)`. The actual IOCTL
//! plumbing lives in `driver.rs`.

// `driver.rs` is Windows-only, so on Linux these items have no
// non-test caller. `cargo test -p agent-windows` still exercises them.
#![allow(dead_code)]

/// Maximum allowlist size accepted by the driver. Mirrors
/// `VIGIL_NETWORK_ISOLATE_MAX_IPS` in `kernel-windows/vigil.h`; entries
/// beyond this are truncated by [`network_isolate_request_buffer`] so a
/// misconfigured manager can't crash the driver.
pub const NETWORK_ISOLATE_MAX_IPS: usize = 256;

/// Build the `IOCTL_VIGIL_NETWORK_ISOLATE` input buffer:
/// `[ Isolate(1) | _Pad(3) | IpCount(4 LE) | IpCount × 16-byte IPv6 ]`.
/// IPv4 entries from `ips` are mapped to v4-mapped IPv6
/// (`::ffff:a.b.c.d`) so the kernel sees one 16-byte shape; the WFP
/// classifiers store entries in that form. Skips entries that don't
/// parse as an IP — operators occasionally include comments or
/// hostnames in the allowlist, and the manager shouldn't refuse to
/// isolate just because one entry is malformed.
pub fn network_isolate_request_buffer(isolate: bool, ips: &[String]) -> Vec<u8> {
    use std::net::IpAddr;

    let mut parsed: Vec<[u8; 16]> = Vec::new();
    for s in ips {
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => parsed.push(v4.to_ipv6_mapped().octets()),
            Ok(IpAddr::V6(v6)) => parsed.push(v6.octets()),
            Err(_) => {
                tracing::warn!(ip = %t, "driver.isolation.allowlist.parse_failed");
            }
        }
        if parsed.len() == NETWORK_ISOLATE_MAX_IPS {
            tracing::warn!(
                cap = NETWORK_ISOLATE_MAX_IPS,
                "driver.isolation.allowlist.truncated"
            );
            break;
        }
    }

    // 1 (Isolate) + 3 (pad) + 4 (IpCount) + N*16.
    let mut buf = Vec::with_capacity(8 + parsed.len() * 16);
    buf.push(if isolate { 1u8 } else { 0u8 });
    buf.push(0);
    buf.push(0);
    buf.push(0);
    buf.extend_from_slice(&(parsed.len() as u32).to_le_bytes());
    for k in &parsed {
        buf.extend_from_slice(k);
    }
    buf
}

#[cfg(test)]
mod network_isolate_buffer_tests {
    //! Phase 1 #1.3 — pin the IOCTL buffer layout. The kernel side reads
    //! these bytes via `VIGIL_NETWORK_ISOLATE_REQ` (see
    //! `kernel-windows/vigil.h`); if the two ever drift, isolation
    //! silently fails (the driver would interpret garbage as IpCount).

    use super::*;

    #[test]
    fn header_on_zero_count() {
        let buf = network_isolate_request_buffer(true, &[]);
        // Isolate=1, three pad bytes, IpCount=0 (LE) → 8 bytes total.
        assert_eq!(buf.len(), 8);
        assert_eq!(buf[0], 1);
        assert_eq!(&buf[1..4], &[0, 0, 0]);
        assert_eq!(&buf[4..8], &0u32.to_le_bytes());
    }

    #[test]
    fn header_off_with_zero_payload() {
        let buf = network_isolate_request_buffer(false, &[]);
        assert_eq!(buf[0], 0);
        assert_eq!(&buf[4..8], &0u32.to_le_bytes());
    }

    #[test]
    fn ipv4_packs_as_v4_mapped_v6() {
        let buf = network_isolate_request_buffer(true, &["10.0.0.42".to_string()]);
        assert_eq!(buf.len(), 8 + 16);
        assert_eq!(buf[0], 1);
        assert_eq!(&buf[4..8], &1u32.to_le_bytes());
        // IPv6 starts at offset 8. First 10 bytes 0, then 0xff 0xff,
        // then the 4 v4 octets.
        assert_eq!(&buf[8..18], &[0u8; 10]);
        assert_eq!(buf[18], 0xff);
        assert_eq!(buf[19], 0xff);
        assert_eq!(&buf[20..24], &[10, 0, 0, 42]);
    }

    #[test]
    fn ipv6_passes_through_unchanged() {
        let buf = network_isolate_request_buffer(true, &["2001:db8::1".to_string()]);
        let expected = std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).octets();
        assert_eq!(&buf[8..24], &expected);
    }

    #[test]
    fn multiple_ips_pack_back_to_back() {
        let buf =
            network_isolate_request_buffer(true, &["10.0.0.1".to_string(), "10.0.0.2".to_string()]);
        assert_eq!(buf.len(), 8 + 32);
        assert_eq!(&buf[4..8], &2u32.to_le_bytes());
        // First entry: 10.0.0.1 — v4 octets at 8 + 12 = 20.
        assert_eq!(&buf[20..24], &[10, 0, 0, 1]);
        // Second entry starts at 8 + 16 = 24; v4 octets at +12 = 36.
        assert_eq!(&buf[36..40], &[10, 0, 0, 2]);
    }

    #[test]
    fn malformed_entries_are_skipped() {
        let buf = network_isolate_request_buffer(
            true,
            &[
                "not-an-ip".to_string(),
                "10.0.0.1".to_string(),
                "".to_string(),
                "::1".to_string(),
            ],
        );
        // Only 10.0.0.1 and ::1 should make it in.
        assert_eq!(&buf[4..8], &2u32.to_le_bytes());
        assert_eq!(buf.len(), 8 + 32);
    }

    #[test]
    fn whitespace_around_ip_is_tolerated() {
        let buf = network_isolate_request_buffer(true, &["  10.0.0.1  ".to_string()]);
        assert_eq!(&buf[4..8], &1u32.to_le_bytes());
        assert_eq!(&buf[20..24], &[10, 0, 0, 1]);
    }

    #[test]
    fn allowlist_is_truncated_at_driver_cap() {
        let ips: Vec<String> = (0..(NETWORK_ISOLATE_MAX_IPS + 50))
            .map(|i| format!("10.0.{}.{}", (i / 256) & 0xff, i & 0xff))
            .collect();
        let buf = network_isolate_request_buffer(true, &ips);
        assert_eq!(&buf[4..8], &(NETWORK_ISOLATE_MAX_IPS as u32).to_le_bytes());
        assert_eq!(buf.len(), 8 + NETWORK_ISOLATE_MAX_IPS * 16);
    }

    #[test]
    fn header_is_exactly_eight_bytes() {
        // The kernel struct VIGIL_NETWORK_ISOLATE_REQ is:
        //   UINT8 Isolate; UINT8 _Pad[3]; UINT32 IpCount;
        // = 1 + 3 + 4 = 8 bytes. Pin it so a drift in either side trips
        // a test rather than silently misaligning the payload.
        let buf = network_isolate_request_buffer(false, &[]);
        assert_eq!(buf.len(), 8, "header must be exactly 8 bytes");
    }
}

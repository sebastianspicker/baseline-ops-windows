//! Shared host fixture for portable planner and authority tests.

pub(crate) fn host(version: &str) -> baselineops_domain::HostIdentityV3 {
    use baselineops_domain::{HostIdentityV3, OsFamily, Sha256Digest};
    let mut host = HostIdentityV3 {
        host_id: "host".into(),
        boot_id: "boot".into(),
        session_id: "session".into(),
        hostname: "endpoint".into(),
        os_family: OsFamily::Windows,
        os_version: version.into(),
        architecture: "x86_64".into(),
        fingerprint: Sha256Digest::of_bytes([]),
    };
    host.fingerprint = host.calculated_fingerprint().expect("fixture fingerprint");
    host
}

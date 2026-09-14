mod ledger;
mod oracle;

use crate::Roots;
use crate::generate::{generated_parity_summary, generated_schemas};
use crate::support::{sorted_files, sorted_files_recursive};
use anyhow::{Context, Result, bail};
use baselineops_domain::{JsonLoadLimits, ProfileV3};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

fn maturity_name(maturity: baselineops_capabilities::ImplementationMaturity) -> &'static str {
    match maturity {
        baselineops_capabilities::ImplementationMaturity::LegacyOnly => "legacy_only",
        baselineops_capabilities::ImplementationMaturity::InDevelopment => "in_development",
        baselineops_capabilities::ImplementationMaturity::CodeComplete => "code_complete",
        baselineops_capabilities::ImplementationMaturity::Implemented => "implemented",
    }
}

pub(crate) fn verify(roots: &Roots) -> Result<()> {
    ledger::verify_registry_and_ledger(roots)?;
    oracle::verify_oracle_inventory(roots)?;
    verify_rust_source_hygiene(roots)?;
    verify_generated_snapshots(roots)?;
    verify_example_profiles(roots)?;
    verify_external_evidence_inventory(roots, false)?;
    verify_no_shell_contract(roots)
}

fn verify_generated_snapshots(roots: &Roots) -> Result<()> {
    verify_schema_snapshots(roots)?;
    verify_parity_snapshot(roots)
}

fn verify_schema_snapshots(roots: &Roots) -> Result<()> {
    for (name, expected) in generated_schemas()? {
        let path = roots.rust.join("schemas").join(name);
        let actual = fs::read(&path)
            .with_context(|| format!("missing generated schema {}", path.display()))?;
        if actual != expected {
            bail!(
                "schema snapshot is stale: {} (run cargo run -p xtask -- generate)",
                path.display()
            );
        }
    }
    Ok(())
}

fn verify_parity_snapshot(roots: &Roots) -> Result<()> {
    let parity_path = roots.rust.join("ledger/capability-parity.md");
    if fs::read_to_string(&parity_path)? != generated_parity_summary(roots)? {
        bail!(
            "parity summary is stale: {} (run cargo run -p xtask -- generate)",
            parity_path.display()
        );
    }
    Ok(())
}

fn verify_example_profiles(roots: &Roots) -> Result<()> {
    for profile in sorted_files(&roots.rust.join("examples/profiles"))? {
        let profile: ProfileV3 =
            baselineops_domain::load_json_file(&profile, JsonLoadLimits::default())?;
        profile
            .validate()
            .with_context(|| format!("invalid example profile {}", profile.id))?;
    }
    Ok(())
}

pub(crate) fn release_check(
    roots: &Roots,
    expected_signer: &str,
    expected_signer_spki_sha256: &str,
    release_tag: &str,
) -> Result<()> {
    verify(roots)?;
    verify_release_identity(expected_signer, expected_signer_spki_sha256, release_tag)?;
    verify_capability_closure()?;
    verify_external_evidence_inventory(roots, true)
}

fn verify_release_identity(
    expected_signer: &str,
    expected_signer_spki_sha256: &str,
    release_tag: &str,
) -> Result<()> {
    let expected_tag = format!("rust-v{}", env!("CARGO_PKG_VERSION"));
    if release_tag != expected_tag {
        bail!("release tag {release_tag} does not match workspace version {expected_tag}");
    }
    if expected_signer.trim().is_empty() || expected_signer == "UNSIGNED-LOCAL-BUILD" {
        bail!("release requires a non-empty external Authenticode signer identity");
    }
    baselineops_windows::SignerSpkiSha256::from_hex(expected_signer_spki_sha256)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(())
}

fn verify_capability_closure() -> Result<()> {
    let registry = baselineops_capabilities::list();
    let incomplete = registry
        .iter()
        .filter(|descriptor| {
            descriptor.maturity != baselineops_capabilities::ImplementationMaturity::Implemented
        })
        .map(|descriptor| descriptor.id)
        .collect::<Vec<_>>();
    if !incomplete.is_empty() {
        bail!(
            "release requires all {} native capabilities to be implemented; incomplete: {}",
            registry.len(),
            incomplete.join(", ")
        );
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceFile {
    schema_version: u8,
    gates: BTreeMap<String, ReleaseEvidenceGate>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceGate {
    closed: bool,
    evidence: String,
}

fn verify_external_evidence_inventory(roots: &Roots, require_closed: bool) -> Result<()> {
    const REQUIRED: [&str; 14] = [
        "authenticated_package_closure",
        "protected_install_runtime",
        "process_spy",
        "gui_accessibility",
        "local_system",
        "windows_11_pro_24h2",
        "windows_11_pro_25h2",
        "windows_11_pro_26h1",
        "windows_11_enterprise_24h2",
        "windows_11_enterprise_25h2",
        "windows_11_enterprise_26h1",
        "hardware_tpm",
        "hardware_secure_boot",
        "hardware_bitlocker",
    ];
    let evidence = read_evidence_inventory(roots, REQUIRED.len())?;
    let mut open = Vec::new();
    for required in REQUIRED {
        if !verified_evidence_gate(&evidence, required)?.closed {
            open.push(required);
        }
    }
    if require_closed && !open.is_empty() {
        bail!("release evidence gates remain open: {}", open.join(", "));
    }
    Ok(())
}

fn read_evidence_inventory(roots: &Roots, required_count: usize) -> Result<ReleaseEvidenceFile> {
    let path = roots.rust.join("release/evidence-gates.json");
    let evidence: ReleaseEvidenceFile = serde_json::from_slice(&fs::read(&path)?)?;
    if evidence.schema_version != 1 || evidence.gates.len() != required_count {
        bail!("release evidence gate inventory is incomplete");
    }
    Ok(evidence)
}

fn verified_evidence_gate<'a>(
    evidence: &'a ReleaseEvidenceFile,
    required: &str,
) -> Result<&'a ReleaseEvidenceGate> {
    let gate = evidence
        .gates
        .get(required)
        .with_context(|| format!("release evidence gate is absent: {required}"))?;
    if gate.evidence.trim().is_empty() {
        bail!("release evidence gate has no evidence reference: {required}");
    }
    Ok(gate)
}

fn verify_no_shell_contract(roots: &Roots) -> Result<()> {
    let forbidden = forbidden_shell_names();
    for path in sorted_files_recursive(&roots.rust)? {
        if !is_handwritten_rust_source(&path, &roots.rust) {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        for token in &forbidden {
            if text.to_ascii_lowercase().contains(token) {
                bail!(
                    "forbidden shell executable token {token} in {}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn forbidden_shell_names() -> [String; 3] {
    [
        ["power", "shell.exe"].concat(),
        ["pw", "sh.exe"].concat(),
        ["c", "md.exe"].concat(),
    ]
}

fn verify_rust_source_hygiene(roots: &Roots) -> Result<()> {
    const MAX_SOURCE_LINES: usize = 600;
    for path in sorted_files_recursive(&roots.rust)? {
        if !is_handwritten_rust_source(&path, &roots.rust) {
            continue;
        }
        let bytes = fs::read(&path)?;
        let line_count = bytes.split(|byte| *byte == b'\n').count();
        if line_count > MAX_SOURCE_LINES {
            bail!(
                "hand-written Rust source exceeds {MAX_SOURCE_LINES} lines: {} ({line_count})",
                path.display()
            );
        }
        if bytes.windows(2).any(|pair| pair == b"\r\n") {
            bail!("hand-written Rust source uses CRLF: {}", path.display());
        }
    }
    Ok(())
}

fn is_handwritten_rust_source(path: &Path, rust_root: &Path) -> bool {
    if path.extension().and_then(|value| value.to_str()) != Some("rs") {
        return false;
    }
    let Ok(relative) = path.strip_prefix(rust_root) else {
        return false;
    };
    !relative
        .components()
        .any(|component| component.as_os_str() == "target" || component.as_os_str() == ".git")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_identity_binds_exact_tag_and_external_signer() {
        let tag = format!("rust-v{}", env!("CARGO_PKG_VERSION"));
        let pin = "ab".repeat(32);
        assert!(verify_release_identity("CN=BaselineOps", &pin, &tag).is_ok());
        assert!(verify_release_identity("CN=BaselineOps", &pin, "rust-v0.0.0").is_err());
        assert!(verify_release_identity("UNSIGNED-LOCAL-BUILD", &pin, &tag).is_err());
        assert!(verify_release_identity(" ", &pin, &tag).is_err());
        assert!(verify_release_identity("CN=BaselineOps", &"AB".repeat(32), &tag).is_err());
    }
}

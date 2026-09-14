use super::maturity_name;
use crate::Roots;
use anyhow::{Context, Result, bail};
use baselineops_capabilities::{ApplyEligibility, CapabilityDescriptor, ImplementationMaturity};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

const ACQUISITION_STUBS: [&str; 3] = [
    "v3.support-bundle.collect",
    "v3.defender.ioc-sweep",
    "v3.ir.artifact-grabber",
];
const PARTIAL_ACQUISITION: [&str; 1] = ["v3.network.emergency-isolation"];
const METADATA_ONLY_PLANS: [&str; 6] = [
    "v3.laps.hygiene",
    "v3.local-admins.guardrail",
    "v3.lsass.vbs-hardening",
    "v3.advanced-audit-policy",
    "v3.credential-guard.vbs",
    "v3.lsa.protection",
];
const MATURITY_KEYS: [&str; 4] = [
    "native_code_complete",
    "native_implemented",
    "in_development",
    "legacy_only",
];

pub(super) fn verify_registry_and_ledger(roots: &Roots) -> Result<()> {
    let registry = baselineops_capabilities::list();
    verify_registry_sequence(registry)?;
    let ledger: Value =
        serde_json::from_slice(&fs::read(roots.rust.join("ledger/capability-parity.json"))?)?;
    let entries = ledger["entries"]
        .as_array()
        .context("ledger entries must be an array")?;
    let summary = ledger["summary"]
        .as_object()
        .context("ledger summary must be an object")?;
    verify_ledger_totals(registry, entries, summary)?;
    verify_ledger_alignment(registry, entries)
}

fn verify_ledger_totals(
    registry: &[CapabilityDescriptor],
    entries: &[Value],
    summary: &serde_json::Map<String, Value>,
) -> Result<()> {
    let registry_counts = count_registry_maturity(registry);
    let ledger_counts = count_ledger_maturity(entries)?;
    verify_matching_maturity_counts(&registry_counts, &ledger_counts)?;
    verify_all_summary_counts(summary, registry.len(), &ledger_counts)
}

fn verify_matching_maturity_counts(
    registry: &BTreeMap<&str, u64>,
    ledger: &BTreeMap<&str, u64>,
) -> Result<()> {
    if registry != ledger {
        bail!("parity ledger entry maturity totals do not match the registry");
    }
    Ok(())
}

fn verify_all_summary_counts(
    summary: &serde_json::Map<String, Value>,
    registry_len: usize,
    ledger_counts: &BTreeMap<&str, u64>,
) -> Result<()> {
    let registry_len = u64::try_from(registry_len)?;
    verify_summary_count(summary, "legacy_capabilities_expected", registry_len)?;
    verify_summary_count(summary, "registry_descriptors", registry_len)?;
    for key in MATURITY_KEYS {
        verify_summary_count(summary, key, ledger_counts[key])?;
    }
    Ok(())
}

fn empty_counts() -> BTreeMap<&'static str, u64> {
    MATURITY_KEYS.into_iter().map(|key| (key, 0)).collect()
}

fn count_registry_maturity(registry: &[CapabilityDescriptor]) -> BTreeMap<&'static str, u64> {
    let mut counts = empty_counts();
    for descriptor in registry {
        counts
            .entry(maturity_summary_key(descriptor.maturity))
            .and_modify(|count| *count += 1);
    }
    counts
}

fn count_ledger_maturity(entries: &[Value]) -> Result<BTreeMap<&'static str, u64>> {
    let mut counts = empty_counts();
    for entry in entries {
        let status = entry["status"]
            .as_str()
            .context("ledger entry status is absent")?;
        let key = ledger_status_summary_key(status)
            .with_context(|| format!("unknown ledger maturity status: {status}"))?;
        counts.entry(key).and_modify(|count| *count += 1);
    }
    Ok(counts)
}

fn verify_summary_count(
    summary: &serde_json::Map<String, Value>,
    key: &str,
    expected: u64,
) -> Result<()> {
    if summary.get(key).and_then(Value::as_u64) != Some(expected) {
        bail!("parity ledger summary field {key} does not match computed entries");
    }
    Ok(())
}

fn maturity_summary_key(maturity: ImplementationMaturity) -> &'static str {
    match maturity {
        ImplementationMaturity::LegacyOnly => "legacy_only",
        ImplementationMaturity::InDevelopment => "in_development",
        ImplementationMaturity::CodeComplete => "native_code_complete",
        ImplementationMaturity::Implemented => "native_implemented",
    }
}

fn ledger_status_summary_key(status: &str) -> Option<&'static str> {
    match status {
        "legacy_only" => Some("legacy_only"),
        "in_development" => Some("in_development"),
        "code_complete" => Some("native_code_complete"),
        "implemented" => Some("native_implemented"),
        _ => None,
    }
}

fn verify_registry_sequence(registry: &[CapabilityDescriptor]) -> Result<()> {
    if registry.len() != 52 {
        bail!("registry must contain exactly 52 capabilities");
    }
    let mut ids = BTreeSet::new();
    for (index, descriptor) in registry.iter().enumerate() {
        if descriptor.legacy_number != u8::try_from(index + 1)? || !ids.insert(descriptor.id) {
            bail!("registry IDs or legacy numbers are incomplete/duplicated");
        }
        verify_descriptor_authority(descriptor)?;
    }
    Ok(())
}

fn verify_descriptor_authority(descriptor: &CapabilityDescriptor) -> Result<()> {
    let enabled = descriptor.apply_eligibility == ApplyEligibility::Enabled;
    let implemented = descriptor.maturity == ImplementationMaturity::Implemented;
    if enabled != descriptor.apply_handler.is_some() || (enabled && !implemented) {
        bail!(
            "capability has inconsistent production Apply authority: {}",
            descriptor.id
        );
    }
    Ok(())
}

fn verify_ledger_alignment(registry: &[CapabilityDescriptor], entries: &[Value]) -> Result<()> {
    if entries.len() != registry.len() {
        bail!("parity ledger entry count must match the registry");
    }
    for (descriptor, entry) in registry.iter().zip(entries) {
        verify_ledger_identity(descriptor, entry)?;
        verify_entry_evidence(descriptor, entry)?;
        verify_operation_requirements(descriptor, entry)?;
    }
    Ok(())
}

fn verify_ledger_identity(descriptor: &CapabilityDescriptor, entry: &Value) -> Result<()> {
    if entry["number"].as_u64() != Some(u64::from(descriptor.legacy_number))
        || entry["id"].as_str() != Some(descriptor.id)
        || entry["script"].as_str() != Some(descriptor.legacy_script)
        || entry["status"].as_str() != Some(maturity_name(descriptor.maturity))
    {
        bail!("parity ledger diverges at capability {}", descriptor.id);
    }
    Ok(())
}

fn verify_entry_evidence(descriptor: &CapabilityDescriptor, entry: &Value) -> Result<()> {
    let evidence = entry["evidence"].as_str().unwrap_or_default();
    let oracle_id = entry["oracle_id"].as_str().unwrap_or_default();
    if evidence.trim().is_empty() || oracle_id.trim().is_empty() {
        bail!("capability evidence is incomplete for {}", descriptor.id);
    }
    if descriptor.maturity == ImplementationMaturity::Implemented
        && entry["status"].as_str() != Some("implemented")
    {
        bail!(
            "implemented capability lacks closed evidence: {}",
            descriptor.id
        );
    }
    Ok(())
}

struct OperationStatuses<'a> {
    audit: &'a str,
    plan: &'a str,
    apply: &'a str,
}

fn operation_statuses(entry: &Value) -> Result<OperationStatuses<'_>> {
    let operations = entry["operation_status"]
        .as_object()
        .context("ledger entry lacks per-operation status")?;
    Ok(OperationStatuses {
        audit: operation_value(operations, "audit")?,
        plan: operation_value(operations, "plan")?,
        apply: operation_value(operations, "apply")?,
    })
}

fn operation_value<'a>(
    operations: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str> {
    operations
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("ledger entry lacks {name} status"))
}

fn verify_operation_requirements(descriptor: &CapabilityDescriptor, entry: &Value) -> Result<()> {
    let operations = operation_statuses(entry)?;
    verify_audit_status(descriptor, operations.audit)?;
    verify_plan_status(descriptor, operations.plan)?;
    verify_known_stub(descriptor, &operations)?;
    verify_apply_status(descriptor, entry, operations.apply)
}

fn verify_audit_status(descriptor: &CapabilityDescriptor, actual: &str) -> Result<()> {
    let expected = if PARTIAL_ACQUISITION.contains(&descriptor.id) {
        "acquisition_partial"
    } else if descriptor.maturity == ImplementationMaturity::InDevelopment {
        "acquisition_unavailable"
    } else {
        "code_complete"
    };
    if descriptor.operations.audit && actual != expected {
        bail!(
            "Audit operation status disagrees with maturity for {}",
            descriptor.id
        );
    }
    Ok(())
}

fn verify_plan_status(descriptor: &CapabilityDescriptor, actual: &str) -> Result<()> {
    let expected = if ACQUISITION_STUBS.contains(&descriptor.id)
        || PARTIAL_ACQUISITION.contains(&descriptor.id)
    {
        "policy_only"
    } else if METADATA_ONLY_PLANS.contains(&descriptor.id) {
        "metadata_only"
    } else {
        "code_complete"
    };
    if descriptor.operations.plan && actual != expected {
        bail!(
            "Plan operation status disagrees with maturity for {}",
            descriptor.id
        );
    }
    Ok(())
}

fn verify_known_stub(
    descriptor: &CapabilityDescriptor,
    operations: &OperationStatuses<'_>,
) -> Result<()> {
    if ACQUISITION_STUBS.contains(&descriptor.id)
        && (descriptor.maturity != ImplementationMaturity::InDevelopment
            || operations.audit != "acquisition_unavailable"
            || operations.plan != "policy_only")
    {
        bail!("known acquisition stub is overstated: {}", descriptor.id);
    }
    if PARTIAL_ACQUISITION.contains(&descriptor.id)
        && descriptor.maturity != ImplementationMaturity::InDevelopment
    {
        bail!("partial acquisition is overstated: {}", descriptor.id);
    }
    Ok(())
}

fn verify_apply_status(
    descriptor: &CapabilityDescriptor,
    entry: &Value,
    actual: &str,
) -> Result<()> {
    if !descriptor.operations.apply {
        if actual != "not_advertised" {
            bail!(
                "non-Apply capability has an invalid Apply status: {}",
                descriptor.id
            );
        }
        return Ok(());
    }
    match descriptor.apply_eligibility {
        ApplyEligibility::Enabled => verify_enabled_apply(descriptor, actual),
        ApplyEligibility::EvidenceRequired => verify_locked_apply(descriptor, entry, actual),
        ApplyEligibility::NotApplicable => {
            bail!("advertised Apply is not eligible: {}", descriptor.id)
        }
    }
}

fn verify_enabled_apply(descriptor: &CapabilityDescriptor, actual: &str) -> Result<()> {
    if actual != "code_complete"
        || descriptor.maturity != ImplementationMaturity::Implemented
        || descriptor.apply_handler.is_none()
    {
        bail!("Apply authority is inconsistent for {}", descriptor.id);
    }
    Ok(())
}

fn verify_locked_apply(
    descriptor: &CapabilityDescriptor,
    entry: &Value,
    actual: &str,
) -> Result<()> {
    let evidence = entry["evidence"].as_str().unwrap_or_default();
    let references = entry["external_evidence_refs"]
        .as_array()
        .context("Apply-capable ledger entry lacks external evidence references")?;
    let has_release_gate = references
        .iter()
        .any(|reference| reference.as_str() == Some("rust/release/evidence-gates.json"));
    if actual != "locked"
        || !has_release_gate
        || descriptor.apply_handler.is_some()
        || !evidence.contains("Apply evidence remains open")
    {
        bail!(
            "Apply lacks explicit open-gate evidence for {}",
            descriptor.id
        );
    }
    Ok(())
}

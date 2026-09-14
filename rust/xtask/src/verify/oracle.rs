use super::maturity_name;
use crate::Roots;
use anyhow::{Context, Result, bail};
use baselineops_capabilities::{
    DohObservation, PolicyValueSnapshot, SecurityOptionsPlan, SemanticPlan, WindowsUpdateConfig,
    WindowsUpdateObservation, WindowsUpdateParameters, build_windows_update_plan, evaluate_doh,
    plan_observed, resolve_windows_update_desired_state,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

mod powershell_logging;

pub(super) fn verify_oracle_inventory(roots: &Roots) -> Result<()> {
    let manifests = read_oracle(roots, "v2-capability-manifests.json")?;
    let fixtures = read_oracle(roots, "v2-neutral-fixtures.json")?;
    let (manifests, fixtures) = oracle_arrays(&manifests, &fixtures)?;
    let fixture_by_id = fixture_index(fixtures)?;
    for (descriptor, manifest) in baselineops_capabilities::list().iter().zip(manifests) {
        verify_manifest(roots, descriptor, manifest, &fixture_by_id)?;
    }
    verify_behavioral_cases(roots, manifests)
}

fn verify_manifest(
    roots: &Roots,
    descriptor: &baselineops_capabilities::CapabilityDescriptor,
    manifest: &Value,
    fixture_by_id: &BTreeMap<&str, &Value>,
) -> Result<()> {
    let fixture_id = manifest["fixture_id"]
        .as_str()
        .context("oracle manifest lacks fixture_id")?;
    verify_manifest_identity(descriptor, manifest)?;
    verify_source_closure(roots, descriptor, manifest)?;
    let fixture = fixture_by_id
        .get(fixture_id)
        .with_context(|| format!("oracle fixture is absent for {}", descriptor.id))?;
    verify_fixture(descriptor, manifest, fixture)
}

fn verify_manifest_identity(
    descriptor: &baselineops_capabilities::CapabilityDescriptor,
    manifest: &Value,
) -> Result<()> {
    let legacy_script = manifest["legacy_script"]
        .as_str()
        .context("oracle manifest lacks legacy_script")?;
    if manifest["number"].as_u64() != Some(u64::from(descriptor.legacy_number))
        || manifest["capability_id"].as_str() != Some(descriptor.id)
        || Path::new(legacy_script)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(descriptor.legacy_script)
        || manifest["rust_maturity"].as_str() != Some(maturity_name(descriptor.maturity))
    {
        bail!("oracle manifest diverges at {}", descriptor.id);
    }
    Ok(())
}

fn verify_source_closure(
    roots: &Roots,
    descriptor: &baselineops_capabilities::CapabilityDescriptor,
    manifest: &Value,
) -> Result<()> {
    let legacy_script = manifest["legacy_script"]
        .as_str()
        .context("oracle manifest lacks legacy_script")?;
    let sources = source_entries(manifest, legacy_script, descriptor.id)?;
    let mut paths = BTreeSet::new();
    let mut closure_index = String::new();
    for source in sources {
        verify_source_member(roots, descriptor.id, source, &mut paths, &mut closure_index)?;
    }
    verify_helper_binding(roots, descriptor.id, legacy_script, &paths)?;
    verify_closure_digests(descriptor.id, manifest, sources, &closure_index)
}

fn source_entries<'a>(manifest: &'a Value, legacy_script: &str, id: &str) -> Result<&'a [Value]> {
    let sources = manifest["source_files"]
        .as_array()
        .context("oracle manifest lacks source_files")?;
    if sources.first().and_then(|source| source["path"].as_str()) != Some(legacy_script) {
        bail!("oracle source closure lacks its entry script for {id}");
    }
    Ok(sources)
}

fn verify_source_member(
    roots: &Roots,
    id: &str,
    source: &Value,
    paths: &mut BTreeSet<String>,
    closure_index: &mut String,
) -> Result<()> {
    let path = source["path"]
        .as_str()
        .context("oracle source closure path is absent")?;
    verify_source_path(id, path, paths)?;
    let actual = verify_source_digest(roots, id, path, source)?;
    writeln!(closure_index, "{actual}  {path}")?;
    Ok(())
}

fn verify_source_path(id: &str, path: &str, paths: &mut BTreeSet<String>) -> Result<()> {
    if !paths.insert(path.to_owned()) || Path::new(path).is_absolute() || path.contains("..") {
        bail!("oracle source closure has an unsafe or duplicate path for {id}");
    }
    Ok(())
}

fn verify_source_digest(roots: &Roots, id: &str, path: &str, source: &Value) -> Result<String> {
    let expected = source["sha256"]
        .as_str()
        .context("oracle source closure digest is absent")?;
    let actual = hex::encode(Sha256::digest(fs::read(roots.repository.join(path))?));
    if expected != actual {
        bail!("oracle source digest drifted for {id} at {path}");
    }
    Ok(actual)
}

fn verify_helper_binding(
    roots: &Roots,
    id: &str,
    legacy_script: &str,
    paths: &BTreeSet<String>,
) -> Result<()> {
    for companion in expected_companion_paths(legacy_script) {
        if roots.repository.join(&companion).is_file() != paths.contains(companion.as_str()) {
            bail!("oracle source closure companion binding drifted for {id}");
        }
    }
    Ok(())
}

fn verify_closure_digests(
    id: &str,
    manifest: &Value,
    sources: &[Value],
    closure_index: &str,
) -> Result<()> {
    if manifest["source_sha256"] != sources[0]["sha256"] {
        bail!("oracle primary source digest diverges for {id}");
    }
    let actual = hex::encode(Sha256::digest(closure_index.as_bytes()));
    if manifest["source_closure_sha256"].as_str() != Some(actual.as_str()) {
        bail!("oracle source closure digest drifted for {id}");
    }
    Ok(())
}

fn expected_companion_paths(legacy_script: &str) -> [String; 2] {
    let stem = Path::new(legacy_script)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    [
        format!("scripts/internal/{stem}.helpers.ps1"),
        format!("scripts/internal/{stem}.runtime.ps1"),
    ]
}

fn verify_fixture(
    descriptor: &baselineops_capabilities::CapabilityDescriptor,
    manifest: &Value,
    fixture: &Value,
) -> Result<()> {
    verify_fixture_binding(descriptor.id, manifest, fixture)?;
    verify_fixture_scope(descriptor.id, fixture)?;
    verify_fixture_fields(descriptor.id, fixture)
}

fn verify_fixture_binding(id: &str, manifest: &Value, fixture: &Value) -> Result<()> {
    if fixture["capability_id"].as_str() != Some(id)
        || fixture["source_sha256"] != manifest["source_sha256"]
        || fixture["source_closure_sha256"] != manifest["source_closure_sha256"]
    {
        bail!("oracle fixture source binding is incomplete for {id}");
    }
    Ok(())
}

fn verify_fixture_scope(id: &str, fixture: &Value) -> Result<()> {
    if fixture["fixture_kind"].as_str() != Some("structural_binding")
        || fixture["proof_scope"].as_str() != Some("structure_only")
        || fixture.get("expected").is_some()
    {
        bail!("oracle fixture overstates its proof scope for {id}");
    }
    Ok(())
}

fn verify_fixture_fields(id: &str, fixture: &Value) -> Result<()> {
    let has_difference = fixture["intentional_safe_parity_differences"]
        .as_array()
        .is_some_and(|differences| !differences.is_empty());
    if !fixture["typed_input"].is_object()
        || !fixture["normalized_observation"].is_object()
        || !fixture["limitations"].is_array()
        || !has_difference
    {
        bail!("oracle fixture contract is incomplete for {id}");
    }
    Ok(())
}

fn fixture_index(fixtures: &[Value]) -> Result<BTreeMap<&str, &Value>> {
    let fixture_by_id = fixtures
        .iter()
        .filter_map(|fixture| fixture["fixture_id"].as_str().map(|id| (id, fixture)))
        .collect::<BTreeMap<_, _>>();
    if fixture_by_id.len() != baselineops_capabilities::list().len() {
        bail!("oracle fixture identifiers are missing or duplicated");
    }
    Ok(fixture_by_id)
}

fn verify_behavioral_cases(roots: &Roots, manifests: &[Value]) -> Result<()> {
    let document = read_oracle(roots, "v2-rust-behavioral-cases.json")?;
    let cases = behavioral_case_array(&document)?;
    verify_behavioral_coverage(&document, cases)?;
    verify_behavioral_entries(cases, manifests)
}

fn verify_behavioral_entries(cases: &[Value], manifests: &[Value]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for case in cases {
        let id = verify_behavioral_identity(case, &mut ids)?;
        verify_behavioral_source(case, manifests)?;
        verify_behavioral_case(case)
            .with_context(|| format!("behavioral oracle mismatch: {id}"))?;
    }
    Ok(())
}

fn verify_behavioral_coverage(document: &Value, cases: &[Value]) -> Result<()> {
    let capabilities = cases
        .iter()
        .filter_map(|case| case["capability_id"].as_str())
        .collect::<BTreeSet<_>>();
    let declared = string_array(&document["coverage"], "behavioral_capabilities")?;
    let expected = capabilities.iter().copied().collect::<Vec<_>>();
    let structural_count = baselineops_capabilities::list().len() - capabilities.len();
    if declared != expected
        || document["coverage"]["proof_scope"].as_str() != Some("partial_policy_behavior")
        || document["coverage"]["structural_only_capability_count"].as_u64()
            != Some(structural_count as u64)
    {
        bail!("behavioral oracle coverage declaration is inaccurate");
    }
    Ok(())
}

fn behavioral_case_array(document: &Value) -> Result<&[Value]> {
    if document["schema_version"].as_u64() != Some(1) {
        bail!("behavioral oracle schema version is unsupported");
    }
    let cases = document["cases"]
        .as_array()
        .context("behavioral oracle cases must be an array")?;
    if cases.is_empty() {
        bail!("behavioral oracle corpus is empty");
    }
    Ok(cases)
}

fn verify_behavioral_identity<'a>(case: &'a Value, ids: &mut BTreeSet<&'a str>) -> Result<&'a str> {
    let id = case["id"]
        .as_str()
        .context("behavioral case ID is absent")?;
    let supported = matches!(
        case["capability_id"].as_str(),
        Some(
            "v3.doh.audit"
                | "v3.powershell.logging"
                | "v3.security-options.drift"
                | "v3.windows-update.policy"
        )
    );
    if !ids.insert(id) || !supported {
        bail!("unsupported or duplicate behavioral oracle case: {id}");
    }
    Ok(id)
}

fn verify_behavioral_source(case: &Value, manifests: &[Value]) -> Result<()> {
    let capability_id = case["capability_id"]
        .as_str()
        .context("behavioral capability ID is absent")?;
    let manifest = manifests
        .iter()
        .find(|manifest| manifest["capability_id"].as_str() == Some(capability_id))
        .context("behavioral case lacks a source manifest")?;
    if case["source_closure_sha256"] != manifest["source_closure_sha256"] {
        bail!("behavioral case source closure drifted for {capability_id}");
    }
    Ok(())
}

fn verify_behavioral_case(case: &Value) -> Result<()> {
    match case["capability_id"].as_str() {
        Some("v3.doh.audit") => verify_doh_behavior(case),
        Some("v3.powershell.logging") => powershell_logging::verify_behavior(case),
        Some("v3.security-options.drift") => verify_security_options_behavior(case),
        Some("v3.windows-update.policy") => verify_windows_update_behavior(case),
        _ => bail!("behavioral case has an unsupported capability"),
    }
}

fn verify_security_options_behavior(case: &Value) -> Result<()> {
    let outcome = case["expected"]["rust_outcome"]
        .as_str()
        .context("Security Options case lacks rust_outcome")?;
    let observed = serde_json::json!({"observation": {"values": case["observation"]}});
    let result = plan_observed("v3.security-options.drift", &case["desired"], &observed);
    if outcome == "rejected" {
        return verify_security_options_rejection(case, &result);
    }
    let SemanticPlan::SecurityOptions(plan) = result.map_err(anyhow::Error::msg)? else {
        bail!("Rust returned the wrong Security Options plan variant");
    };
    verify_security_options_plan(case, outcome, &plan)
}

fn verify_security_options_rejection(
    case: &Value,
    result: &std::result::Result<SemanticPlan, String>,
) -> Result<()> {
    if result.is_ok() {
        bail!("Security Options input expected to be rejected was accepted");
    }
    if case["expected"]["intentional_safe_parity_difference"].is_null() {
        bail!("Security Options rejection difference is not evidenced");
    }
    Ok(())
}

fn verify_security_options_plan(
    case: &Value,
    outcome: &str,
    plan: &SecurityOptionsPlan,
) -> Result<()> {
    let actual = normalized_security_options_changes(plan);
    if outcome != "planned"
        || plan.apply_available
        || actual != case["expected"]["normalized_mutations"]
    {
        bail!("Rust Security Options plan diverges from the shared normalized result");
    }
    Ok(())
}

fn normalized_security_options_changes(plan: &SecurityOptionsPlan) -> Value {
    let mut changes = plan
        .proposed_changes
        .iter()
        .map(|change| {
            serde_json::json!({
                "field": change.field,
                "current": change.observed,
                "desired": change.desired,
            })
        })
        .collect::<Vec<_>>();
    changes.sort_by(|left, right| left["field"].as_str().cmp(&right["field"].as_str()));
    Value::Array(changes)
}

fn verify_windows_update_behavior(case: &Value) -> Result<()> {
    let resolved = parse_windows_update_desired(&case["desired"]);
    let expected_outcome = case["expected"]["rust_outcome"]
        .as_str()
        .context("Windows Update case lacks rust_outcome")?;
    if expected_outcome == "rejected" {
        return verify_windows_update_rejection(case, &resolved);
    }
    verify_windows_update_plan(case, expected_outcome, resolved?)
}

fn verify_windows_update_rejection(
    case: &Value,
    resolved: &Result<WindowsUpdateConfig>,
) -> Result<()> {
    if resolved.is_ok() {
        bail!("Windows Update input expected to be rejected was accepted");
    }
    if case["expected"]["intentional_safe_parity_difference"].is_null() {
        bail!("Windows Update rejection difference is not evidenced");
    }
    Ok(())
}

fn verify_windows_update_plan(
    case: &Value,
    expected_outcome: &str,
    desired: WindowsUpdateConfig,
) -> Result<()> {
    let observation: WindowsUpdateObservation = serde_json::from_value(serde_json::json!({
        "values": case["observation"],
    }))?;
    let plan = build_windows_update_plan(observation, desired);
    let actual = normalized_windows_update_mutations(&plan)?;
    if expected_outcome != "planned" || actual != case["expected"]["normalized_mutations"] {
        bail!("Rust Windows Update plan diverges from the shared normalized result");
    }
    Ok(())
}

fn parse_windows_update_desired(value: &Value) -> Result<WindowsUpdateConfig> {
    let desired: WindowsUpdateConfig = serde_json::from_value(value.clone())?;
    resolve_windows_update_desired_state(&WindowsUpdateParameters {
        desired: Some(desired),
        config: None,
    })
    .map_err(anyhow::Error::msg)
}

fn normalized_windows_update_mutations(
    plan: &baselineops_capabilities::WindowsUpdatePlan,
) -> Result<Value> {
    let mut mutations = plan
        .mutations
        .iter()
        .map(|mutation| {
            let current = plan
                .observation
                .values
                .get(&mutation.field)
                .cloned()
                .unwrap_or(PolicyValueSnapshot::Missing);
            Ok(serde_json::json!({
                "field": mutation.field,
                "current": current,
                "desired": mutation.desired,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    mutations.sort_by(|left, right| left["field"].as_str().cmp(&right["field"].as_str()));
    Ok(Value::Array(mutations))
}

fn verify_doh_behavior(case: &Value) -> Result<()> {
    let audit = evaluate_doh(&doh_observation(&case["observation"])?);
    verify_doh_expected(&audit, &case["expected"])
}

fn doh_observation(observation: &Value) -> Result<DohObservation> {
    Ok(DohObservation {
        enable_auto_doh: optional_u32(observation, "enable_auto_doh")?,
        name_servers: string_array(observation, "name_servers")?,
        bootstrap_addresses: string_array(observation, "bootstrap_addresses")?,
        block_untrusted_doh: optional_u32(observation, "block_untrusted_doh")?,
        server_query_failed: observation["server_query_failed"]
            .as_bool()
            .context("server_query_failed must be a Boolean")?,
    })
}

fn verify_doh_expected(audit: &baselineops_capabilities::DohAudit, expected: &Value) -> Result<()> {
    let expected_codes = string_array(expected, "finding_codes")?;
    let actual_codes = audit
        .findings
        .iter()
        .map(|finding| finding.code.to_owned())
        .collect::<Vec<_>>();
    if expected["mode"].as_str() != Some(audit.mode.as_str()) {
        bail!("Rust DoH policy mode diverges from the shared expected result");
    }
    if expected_codes != actual_codes {
        bail!("Rust DoH policy findings diverge from the shared expected result");
    }
    Ok(())
}

fn optional_u32(value: &Value, field: &str) -> Result<Option<u32>> {
    if value[field].is_null() {
        return Ok(None);
    }
    let raw = value[field]
        .as_u64()
        .with_context(|| format!("{field} must be null or an integer"))?;
    Ok(Some(u32::try_from(raw)?))
}

fn string_array(value: &Value, field: &str) -> Result<Vec<String>> {
    value[field]
        .as_array()
        .with_context(|| format!("{field} must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .with_context(|| format!("{field} entries must be strings"))
        })
        .collect()
}

fn read_oracle(roots: &Roots, name: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(
        roots.rust.join("oracles").join(name),
    )?)?)
}

fn oracle_arrays<'a>(
    manifests: &'a Value,
    fixtures: &'a Value,
) -> Result<(&'a [Value], &'a [Value])> {
    if manifests["schema_version"].as_u64() != Some(2)
        || fixtures["schema_version"].as_u64() != Some(2)
    {
        bail!("oracle structural binding schema version is unsupported");
    }
    let manifests = manifests["manifests"]
        .as_array()
        .context("oracle manifests must be an array")?;
    let fixtures = fixtures["fixtures"]
        .as_array()
        .context("oracle fixtures must be an array")?;
    let expected = baselineops_capabilities::list().len();
    if manifests.len() != expected || fixtures.len() != expected {
        bail!("oracle inventory must match the capability registry");
    }
    Ok((manifests, fixtures))
}

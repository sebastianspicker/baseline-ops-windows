use crate::Roots;
use anyhow::{Context, Result, bail};
use baselineops_domain::{FindingV3, PlanV3, ProfileV3, ResultV3};
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::fs;
use std::process::Command;

pub(crate) fn generate(roots: &Roots) -> Result<()> {
    write_generated_schemas(roots)?;
    let sbom = generate_sbom(roots)?;
    baselineops_windows::atomic_write(roots.rust.join("schemas/workspace.cdx.json"), &sbom)?;
    let parity = generated_parity_summary(roots)?;
    baselineops_windows::atomic_write(
        roots.rust.join("ledger/capability-parity.md"),
        parity.as_bytes(),
    )?;
    Ok(())
}

fn write_generated_schemas(roots: &Roots) -> Result<()> {
    fs::create_dir_all(roots.rust.join("schemas"))?;
    for (name, bytes) in generated_schemas()? {
        baselineops_windows::atomic_write(roots.rust.join("schemas").join(name), &bytes)?;
    }
    Ok(())
}

pub(crate) fn generated_parity_summary(roots: &Roots) -> Result<String> {
    let ledger = read_parity_ledger(roots)?;
    let summary = ledger["summary"]
        .as_object()
        .context("ledger summary must be an object")?;
    let entries = ledger["entries"]
        .as_array()
        .context("ledger entries must be an array")?;
    let mut output = String::from(
        "# Human-readable capability parity summary\n\nThis table shows the Rust implementation status of the 52 numbered PowerShell capabilities. It excludes the `00-*` orchestration helpers and is generated from [`capability-parity.json`](capability-parity.json), which records the status and evidence for each capability.\n\nA capability marked `code_complete` can run Audit and Plan. Production Apply also requires reviewed Windows evidence, an `implemented` status, and permission compiled into the application.\n\n",
    );
    append_parity_totals(&mut output, summary)?;
    output.push_str(
        "\n## Capabilities\n\n| Legacy | Stable v3 ID | Script | Maturity | Apply | Oracle |\n| --- | --- | --- | --- | --- | --- |\n",
    );
    for entry in entries {
        append_parity_entry(&mut output, entry)?;
    }
    output.push_str(
        "\nEach entry identifies a tracked structural test fixture and the complete set of current PowerShell v2 source files it covers, including extracted helpers. These fixtures check structure, not equivalent behavior. The separate behavioral tests record only the operations actually compared.\n\nRust intentionally rejects legacy mechanisms that let input data choose paths, URLs, executables, arguments, or credentials, or authorize registry, network, or output operations. These restrictions are deliberate safety differences from PowerShell behavior.\n\nWindows VM, LocalSystem, signing, protected-install, hardware, accessibility, TPM, Secure Boot, and BitLocker checks are still outstanding. See [`../release/evidence-gates.json`](../release/evidence-gates.json) for the remaining requirements. This table does not establish release readiness.\n",
    );
    Ok(output)
}

fn append_parity_totals(
    output: &mut String,
    summary: &serde_json::Map<String, Value>,
) -> Result<()> {
    output.push_str("## Totals\n\n");
    for key in [
        "legacy_capabilities_expected",
        "registry_descriptors",
        "native_code_complete",
        "native_implemented",
        "in_development",
        "legacy_only",
    ] {
        let value = summary
            .get(key)
            .and_then(Value::as_u64)
            .with_context(|| format!("ledger summary field is absent: {key}"))?;
        writeln!(output, "- `{key}`: {value}").expect("writing to a String cannot fail");
    }
    Ok(())
}

fn append_parity_entry(output: &mut String, entry: &Value) -> Result<()> {
    let number = entry["number"].as_u64().context("entry number is absent")?;
    let id = entry["id"].as_str().context("entry ID is absent")?;
    let script = entry["script"].as_str().context("entry script is absent")?;
    let status = entry["status"].as_str().context("entry status is absent")?;
    let eligibility = entry["apply_eligibility"]
        .as_str()
        .context("entry Apply eligibility is absent")?;
    let oracle = entry["oracle_id"]
        .as_str()
        .context("entry oracle ID is absent")?;
    writeln!(
        output,
        "| {number:02} | `{id}` | `{script}` | `{status}` | `{eligibility}` | `{oracle}` |"
    )
    .expect("writing to a String cannot fail");
    Ok(())
}

pub(crate) fn generated_schemas() -> Result<Vec<(&'static str, Vec<u8>)>> {
    Ok(vec![
        (
            "profile-v3.schema.json",
            schema_bytes(&schemars::schema_for!(ProfileV3))?,
        ),
        (
            "plan-v4.schema.json",
            schema_bytes(&schemars::schema_for!(PlanV3))?,
        ),
        (
            "result-v3.schema.json",
            schema_bytes(&schemars::schema_for!(ResultV3))?,
        ),
        (
            "finding-v3.schema.json",
            schema_bytes(&schemars::schema_for!(FindingV3))?,
        ),
    ])
}

fn schema_bytes(schema: &schemars::Schema) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(schema)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn generate_sbom(roots: &Roots) -> Result<Vec<u8>> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(&roots.rust)
        .output()?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)?;
    let components = metadata["packages"]
        .as_array()
        .context("cargo metadata packages are absent")?
        .iter()
        .map(|package| {
            json!({
                "type": "library",
                "name": package["name"],
                "version": package["version"],
                "purl": format!("pkg:cargo/{}@{}", package["name"].as_str().unwrap_or_default(), package["version"].as_str().unwrap_or_default())
            })
        })
        .collect::<Vec<_>>();
    let sbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": { "component": { "type": "application", "name": "BaselineOps for Windows", "version": env!("CARGO_PKG_VERSION") } },
        "components": components
    });
    let mut bytes = serde_json::to_vec_pretty(&sbom)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_parity_ledger(roots: &Roots) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(
        roots.rust.join("ledger/capability-parity.json"),
    )?)?)
}

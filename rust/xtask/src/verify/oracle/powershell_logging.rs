use anyhow::{Context, Result, bail};
use baselineops_capabilities::{
    PowerShellLoggingMutation, PowerShellLoggingPlan, SemanticPlan, plan_observed,
};
use serde_json::Value;

pub(super) fn verify_behavior(case: &Value) -> Result<()> {
    let expected = &case["expected"];
    let outcome = expected["rust_outcome"]
        .as_str()
        .context("PowerShell Logging case lacks rust_outcome")?;
    let result = plan_observed(
        "v3.powershell.logging",
        &case["desired"],
        &case["observation"],
    );
    if outcome == "rejected" {
        return verify_rejection(expected, &result);
    }
    let SemanticPlan::PowerShellLogging(plan) = result.map_err(anyhow::Error::msg)? else {
        bail!("Rust returned the wrong PowerShell Logging plan variant");
    };
    verify_plan(expected, outcome, &plan)
}

fn verify_rejection(
    expected: &Value,
    result: &std::result::Result<SemanticPlan, String>,
) -> Result<()> {
    if result.is_ok() {
        bail!("PowerShell Logging input expected to be rejected was accepted");
    }
    if expected["intentional_safe_parity_difference"].is_null()
        || expected["normalized_mutations"] != serde_json::json!([])
    {
        bail!("PowerShell Logging rejection difference is not evidenced");
    }
    Ok(())
}

fn verify_plan(expected: &Value, outcome: &str, plan: &PowerShellLoggingPlan) -> Result<()> {
    if outcome != "planned"
        || normalized_mutations(plan) != expected["normalized_mutations"]
        || !plan.requires_administrator
        || plan.reboot_required
    {
        bail!("Rust PowerShell Logging plan diverges from the shared normalized result");
    }
    Ok(())
}

fn normalized_mutations(plan: &PowerShellLoggingPlan) -> Value {
    let mut mutations = plan
        .mutations
        .iter()
        .map(normalized_mutation)
        .collect::<Vec<_>>();
    mutations.sort_by(|left, right| left["field"].as_str().cmp(&right["field"].as_str()));
    Value::Array(mutations)
}

fn normalized_mutation(mutation: &PowerShellLoggingMutation) -> Value {
    match mutation {
        PowerShellLoggingMutation::SetDword { field, value } => serde_json::json!({
            "field": serde_json::to_value(field).expect("policy field serializes"),
            "type": "dword",
            "value": value,
        }),
        PowerShellLoggingMutation::SetString { field, value } => serde_json::json!({
            "field": serde_json::to_value(field).expect("policy field serializes"),
            "type": "string",
            "value": value,
        }),
        PowerShellLoggingMutation::ReplaceModuleNames { values } => serde_json::json!({
            "field": "module_names",
            "type": "numbered_strings",
            "value": values.iter().map(|(name, value)| serde_json::json!({
                "name": name,
                "value": value,
            })).collect::<Vec<_>>(),
        }),
    }
}

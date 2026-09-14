//! Pure proposal derivation from captured evidence. This module performs no I/O.

use crate as policy;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

/// Capability-owned proposal variants, never executable command text.
///
/// These values are serialized into a plan for review. Only a fresh invocation
/// of this planner may produce worker authority; deserialization does not.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "proposal", rename_all = "snake_case")]
pub enum SemanticPlan {
    /// Explicit observation with no endpoint mutation or recovery requirement.
    Observation {
        /// Original bounded evidence, including any missing/denied fields.
        result: Value,
        /// Explains why no change is proposed.
        reason: &'static str,
    },
    /// Fixed ASR metadata proposal.
    DefenderAsr(policy::DefenderAsrAllowlistPlan),
    /// Finite Office and browser registry policy changes.
    OfficeBrowser(policy::OfficeBrowserPlan),
    /// Finite Windows Update registry policy changes.
    WindowsUpdate(policy::WindowsUpdatePlan),
    /// Update health evidence without repair authority.
    UpdateHealth(policy::UpdateHealthReadOnlyPlan),
    /// Fixed scheduled-task evidence without task mutation authority.
    ScheduledTasks(policy::ScheduledTasksReadOnlyPlan),
    /// `WinGet` evidence without dynamic DSC execution.
    Winget(policy::WingetReadOnlyPlan),
    /// Fixed remote-access guardrail proposal.
    RemoteGuardrails(policy::RemoteGuardrailsPlan),
    /// Sysmon evidence without resource execution authority.
    Sysmon(policy::SysmonReadOnlyPlan),
    /// Finite firewall profile policy proposal.
    FirewallBaseline(policy::FirewallBaselinePlan),
    /// Bounded isolation proposal with explicit recovery.
    EmergencyIsolation(policy::EmergencyIsolationPlan),
    /// Finite local SMB policy proposal.
    SmbEncryption(policy::SmbEncryptionPlan),
    /// Finite PowerShell logging registry policy changes.
    PowerShellLogging(policy::PowerShellLoggingPlan),
    /// Fixed firewall logging drift proposal.
    FirewallLogging(policy::FirewallLoggingPlan),
    /// Finite Security Options registry policy proposal.
    SecurityOptions(policy::SecurityOptionsPlan),
    /// Fixed Defender policy proposal.
    DefenderRansomware(policy::DefenderRansomwarePlan),
}

impl SemanticPlan {
    /// Whether the proposal contains any endpoint changes, independently of eligibility.
    #[must_use]
    pub fn proposes_changes(&self) -> bool {
        self.registry_changes()
            .or_else(|| self.network_changes())
            .or_else(|| self.security_changes())
            .unwrap_or(false)
    }

    fn registry_changes(&self) -> Option<bool> {
        match self {
            Self::OfficeBrowser(plan) => Some(!plan.mutations.is_empty()),
            Self::WindowsUpdate(plan) => Some(!plan.mutations.is_empty()),
            Self::PowerShellLogging(plan) => Some(!plan.mutations.is_empty()),
            Self::SecurityOptions(plan) => Some(!plan.proposed_changes.is_empty()),
            _ => None,
        }
    }
    fn network_changes(&self) -> Option<bool> {
        match self {
            Self::RemoteGuardrails(plan) => Some(!plan.proposed_changes.is_empty()),
            Self::FirewallBaseline(plan) => Some(!plan.proposed_changes.is_empty()),
            Self::SmbEncryption(plan) => Some(!plan.proposed_changes.is_empty()),
            Self::FirewallLogging(plan) => Some(!plan.drift.is_empty()),
            _ => None,
        }
    }
    fn security_changes(&self) -> Option<bool> {
        match self {
            Self::DefenderRansomware(plan) => Some(!plan.proposed_changes.is_empty()),
            Self::EmergencyIsolation(plan) => Some(!plan.actions.is_empty()),
            _ => None,
        }
    }
}

/// Derive a capability-specific proposal from the exact captured audit evidence.
///
/// Parameters retain profile v3 semantics. No Windows collector is invoked here,
/// and missing observations never become defaults. Read-only capabilities remain
/// explicit observations when included in an Apply-oriented profile.
///
/// # Errors
///
/// Rejects unknown capabilities, malformed observations/parameters, or an unsafe
/// or incomplete proposal rejected by the capability's pure planner.
pub fn plan_observed(
    id: &str,
    parameters: &Value,
    observed: &Value,
) -> Result<SemanticPlan, String> {
    let descriptor = policy::lookup(id).ok_or_else(|| format!("unknown capability {id}"))?;
    require_observation(observed)?;
    if let Some((_, planner)) = PLANNERS.iter().find(|(registered, _)| *registered == id) {
        planner(parameters, observed)
    } else {
        Ok(SemanticPlan::Observation {
            result: observed.clone(),
            reason: if matches!(descriptor.legacy_number, 2 | 3 | 13 | 33 | 39 | 40) {
                "This capability currently provides observation only; native remediation is not implemented."
            } else {
                "This capability is read-only; no endpoint change is proposed."
            },
        })
    }
}

fn require_observation(observed: &Value) -> Result<(), String> {
    if !observed.is_object() || observed.as_object().is_some_and(serde_json::Map::is_empty) {
        return Err("native observation must be a nonempty object".into());
    }
    Ok(())
}

type Planner = fn(&Value, &Value) -> Result<SemanticPlan, String>;
const PLANNERS: &[(&str, Planner)] = &[
    ("v3.defender.asr-allowlist", defender_asr),
    ("v3.office-browser.hardening", office_browser),
    ("v3.windows-update.policy", windows_update),
    ("v3.update-health.ssu", update_health),
    ("v3.scheduled-tasks.hygiene", scheduled_tasks),
    (policy::WINGET_SELF_HEAL_ID, winget_self_heal),
    (policy::WINGET_CONFIGURATION_ID, winget_configuration),
    ("v3.remote-access.guardrails", remote_guardrails),
    ("v3.sysmon.config", sysmon),
    ("v3.sysmon.rule-drift", sysmon),
    ("v3.firewall.baseline", firewall_baseline),
    ("v3.network.emergency-isolation", emergency_isolation),
    ("v3.smb.encryption", smb_encryption),
    ("v3.powershell.logging", powershell_logging),
    ("v3.firewall.logging", firewall_logging),
    ("v3.security-options.drift", security_options),
    (
        "v3.defender.ransomware-network-protection",
        defender_ransomware,
    ),
];

fn defender_asr(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    Ok(SemanticPlan::DefenderAsr(
        policy::build_defender_asr_allowlist_plan(observation(observed)?, &decode(parameters)?),
    ))
}
fn update_health(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    let _: policy::UpdateHealthParameters = decode(parameters)?;
    Ok(SemanticPlan::UpdateHealth(
        policy::build_update_health_read_only_plan(observation(observed)?),
    ))
}
fn scheduled_tasks(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    let _: policy::ScheduledTasksParameters = decode(parameters)?;
    Ok(SemanticPlan::ScheduledTasks(
        policy::build_scheduled_tasks_read_only_plan(observation(observed)?),
    ))
}
fn winget_self_heal(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    winget(parameters, observed, policy::evaluate_winget_self_heal)
}
fn winget_configuration(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    winget(parameters, observed, policy::evaluate_winget_configuration)
}
fn winget(
    parameters: &Value,
    observed: &Value,
    evaluator: fn(policy::WingetObservation) -> policy::WingetAudit,
) -> Result<SemanticPlan, String> {
    let _: policy::WingetParameters = decode(parameters)?;
    Ok(SemanticPlan::Winget(policy::build_winget_read_only_plan(
        evaluator(observation(observed)?),
    )))
}
fn remote_guardrails(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    Ok(SemanticPlan::RemoteGuardrails(
        policy::build_remote_guardrails_plan(observation(observed)?, &decode(parameters)?)?,
    ))
}
fn sysmon(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    Ok(SemanticPlan::Sysmon(policy::build_sysmon_read_only_plan(
        policy::evaluate_sysmon(observation(observed)?, &decode(parameters)?),
    )))
}
fn firewall_baseline(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    Ok(SemanticPlan::FirewallBaseline(
        policy::build_firewall_baseline_plan(observation(observed)?, &decode(parameters)?)?,
    ))
}
fn emergency_isolation(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    let observation = observation(observed)?;
    let policy = decode(parameters)?;
    crate::emergency_isolation_policy::validate_emergency_isolation_preflight(
        &observation,
        &policy,
    )?;
    Ok(SemanticPlan::EmergencyIsolation(
        policy::build_emergency_isolation_plan(observation, &policy),
    ))
}
fn smb_encryption(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    Ok(SemanticPlan::SmbEncryption(
        policy::build_smb_encryption_plan(observation(observed)?, &decode(parameters)?)?,
    ))
}
fn powershell_logging(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    Ok(SemanticPlan::PowerShellLogging(
        policy::build_powershell_logging_plan(
            decode(observed)?,
            policy::resolve_powershell_logging_desired_state(&decode(parameters)?)?,
        )?,
    ))
}
fn firewall_logging(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    Ok(SemanticPlan::FirewallLogging(
        policy::build_firewall_logging_plan(
            decode(observed)?,
            policy::resolve_firewall_logging_desired_state(&decode(parameters)?)?,
        )?,
    ))
}
fn defender_ransomware(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    Ok(SemanticPlan::DefenderRansomware(
        policy::build_defender_ransomware_plan(observation(observed)?, &decode(parameters)?),
    ))
}

fn decode<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}

fn observation<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    decode(
        value
            .get("observation")
            .ok_or("captured native observation is absent")?,
    )
}

fn office_browser(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    let plan = policy::build_office_browser_plan(
        decode(observed)?,
        policy::resolve_office_browser_desired_state(&decode(parameters)?)?,
    );
    if plan
        .mutations
        .iter()
        .any(|mutation| !plan.observation.values.contains_key(&mutation.field))
    {
        return Err("Office/browser snapshot omits required policy fields".into());
    }
    Ok(SemanticPlan::OfficeBrowser(plan))
}

fn windows_update(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    let plan = policy::build_windows_update_plan(
        decode(observed)?,
        policy::resolve_windows_update_desired_state(&decode(parameters)?)?,
    );
    if plan
        .mutations
        .iter()
        .any(|mutation| !plan.observation.values.contains_key(&mutation.field))
    {
        return Err("Windows Update snapshot omits required policy fields".into());
    }
    Ok(SemanticPlan::WindowsUpdate(plan))
}

fn security_options(parameters: &Value, observed: &Value) -> Result<SemanticPlan, String> {
    let plan = policy::build_security_options_plan(observation(observed)?, &decode(parameters)?);
    if plan.audit.desired.keys().any(|field| {
        !matches!(
            plan.audit.observation.values.get(field),
            Some(
                policy::SecurityOptionEvidence::Present(_)
                    | policy::SecurityOptionEvidence::Missing
            )
        )
    }) {
        return Err("Security Options snapshot has missing or unreadable evidence".into());
    }
    Ok(SemanticPlan::SecurityOptions(plan))
}

#[cfg(test)]
#[path = "semantic_plan_tests.rs"]
mod tests;

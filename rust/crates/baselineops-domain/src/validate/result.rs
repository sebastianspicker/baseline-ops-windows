use std::collections::BTreeSet;

use crate::{ActionId, ActionResultV3, DomainResult, FindingId, FindingV3, ResultV3};

use super::{
    validate_action_result, validate_artifacts, validate_json_map, validate_nonempty, validation,
};

impl ResultV3 {
    /// Validates result timestamps, references, findings, and bounded evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid timestamps, identity, summary, metadata, references, or evidence.
    pub fn validate(&self) -> DomainResult<()> {
        validate_result_header(self)?;
        validate_result_actions(&self.actions)?;
        validate_result_findings(&self.findings)?;
        validate_artifacts(&self.artifacts)
    }
}

fn validate_result_header(result: &ResultV3) -> DomainResult<()> {
    validate_result_times(result)?;
    result.host.validate()?;
    validate_nonempty("result summary", &result.summary, 4096)?;
    validate_json_map("result metadata", &result.metadata)
}

fn validate_result_times(result: &ResultV3) -> DomainResult<()> {
    if result.completed_at < result.started_at {
        return validation("result completion time must not precede its start time");
    }
    Ok(())
}

fn validate_result_actions(actions: &[ActionResultV3]) -> DomainResult<()> {
    let mut action_ids = BTreeSet::new();
    for action in actions {
        validate_result_action(action, &mut action_ids)?;
    }
    Ok(())
}

fn validate_result_action(
    action: &ActionResultV3,
    action_ids: &mut BTreeSet<ActionId>,
) -> DomainResult<()> {
    validate_action_result(action)?;
    if !action_ids.insert(action.action_id) {
        return validation("result contains duplicate action result IDs");
    }
    Ok(())
}

fn validate_result_findings(findings: &[FindingV3]) -> DomainResult<()> {
    let mut finding_ids = BTreeSet::new();
    for finding in findings {
        validate_result_finding(finding, &mut finding_ids)?;
    }
    Ok(())
}

fn validate_result_finding(
    finding: &FindingV3,
    finding_ids: &mut BTreeSet<FindingId>,
) -> DomainResult<()> {
    finding.validate()?;
    if !finding_ids.insert(finding.id) {
        return validation("result contains duplicate finding IDs");
    }
    Ok(())
}

impl FindingV3 {
    /// Validates a finding's stable automation fields and evidence bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid code, message, or evidence.
    pub fn validate(&self) -> DomainResult<()> {
        validate_nonempty("finding code", &self.code, 128)?;
        validate_nonempty("finding message", &self.message, 4096)?;
        validate_json_map("finding evidence", &self.evidence)
    }
}

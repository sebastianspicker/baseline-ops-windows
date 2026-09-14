use baselineops_domain::{
    ActionReceiptV3, ArtifactV3, PlanId, ResultId, ResultStatus, RunId, Sha256Digest,
};
use serde::{Deserialize, Serialize};

/// Internal on-disk schema, distinct from the IPC result envelope.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResultDocument {
    pub(crate) schema_version: String,
    pub(crate) result_id: ResultId,
    pub(crate) plan_id: PlanId,
    pub(crate) run_id: RunId,
    pub(crate) plan_digest: Sha256Digest,
    pub(crate) journal_prefix_hash: Sha256Digest,
    pub(crate) receipts: Vec<ActionReceiptV3>,
    pub(crate) status: ResultStatus,
    pub(crate) reason: Option<String>,
    pub(crate) reboot_possible: bool,
    pub(crate) artifacts: Vec<ArtifactV3>,
}

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ActionId, CapabilityId, DomainError, DomainResult, LogicalResourceId, Sha256Digest,
    canonical_json_digest,
};

use super::{JsonMap, OsFamily};

/// Identity information that binds a plan to the intended endpoint.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HostIdentityV3 {
    /// Stable worker-defined endpoint identifier, not an authentication secret.
    pub host_id: String,
    /// Operating-system boot identifier; prevents a plan crossing a reboot boundary.
    pub boot_id: String,
    /// Worker session identifier; prevents replay through another local session.
    pub session_id: String,
    /// Current computer name for operator display.
    pub hostname: String,
    /// Operating-system family.
    pub os_family: OsFamily,
    /// Operating-system version returned by the worker.
    pub os_version: String,
    /// CPU architecture label.
    pub architecture: String,
    /// Canonical digest binding these identity fields.
    pub fingerprint: Sha256Digest,
}

/// Build identity of the component that created or validates a plan.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ToolIdentityV3 {
    /// Tool name, normally `baselineops`.
    pub name: String,
    /// Tool version.
    pub version: String,
    /// Optional build or package digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_digest: Option<Sha256Digest>,
}

/// The origin category of profile or configuration input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A local, operator-supplied file.
    LocalFile,
    /// A profile embedded in the signed distribution.
    Bundled,
    /// A source retrieved through an explicitly trusted remote workflow.
    Remote,
    /// Input constructed by a caller through the public API.
    Api,
}

/// Source provenance that remains stable enough to validate at apply time.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SourceIdentityV3 {
    /// Origin category.
    pub kind: SourceKind,
    /// Operator-readable origin label or normalized URI.
    pub locator: String,
    /// Digest of the source content as received.
    pub digest: Sha256Digest,
}

/// Digest identity of a profile and capability input bundle.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InputIdentityV3 {
    /// Canonical digest of all input bytes that affect the plan.
    pub digest: Sha256Digest,
    /// Number of input bytes used to calculate the digest.
    pub size_bytes: u64,
}

/// Shape of an operator-bound external resource.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// One bounded regular file.
    File,
    /// A deterministic manifest of bounded regular files.
    DirectoryManifest,
}

/// Path-free digest binding for one logical external resource.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ResourceBindingV3 {
    /// Logical identifier referenced by typed capability input.
    pub logical_id: LogicalResourceId,
    /// Whether the broker bound a file or a directory manifest.
    pub kind: ResourceKind,
    /// Digest of the file bytes or canonical directory manifest.
    pub digest: Sha256Digest,
    /// Total bounded input bytes represented by this binding.
    pub size_bytes: u64,
}

impl InputIdentityV3 {
    /// Bind profile bytes and every external resource into one input closure.
    ///
    /// # Errors
    ///
    /// Returns an error if resource sizes overflow or the canonical closure cannot be encoded.
    pub fn from_resources(
        profile_digest: Sha256Digest,
        profile_size: u64,
        resources: &[ResourceBindingV3],
    ) -> DomainResult<Self> {
        #[derive(Serialize)]
        struct InputClosure<'a> {
            profile_digest: Sha256Digest,
            resources: &'a [ResourceBindingV3],
        }
        let resource_size = resources.iter().try_fold(0_u64, |total, resource| {
            total
                .checked_add(resource.size_bytes)
                .ok_or_else(|| DomainError::Validation("input resource size overflowed".into()))
        })?;
        Ok(Self {
            digest: canonical_json_digest(&InputClosure {
                profile_digest,
                resources,
            })?,
            size_bytes: profile_size
                .checked_add(resource_size)
                .ok_or_else(|| DomainError::Validation("input closure size overflowed".into()))?,
        })
    }
}

/// A capability-provided value captured before planning.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ObservedValueV3 {
    /// Capability observed for this exact profile step.
    pub capability: CapabilityId,
    /// Canonical digest of the parameters used during observation.
    pub parameters_digest: Sha256Digest,
    /// Time the capability observed this value.
    pub observed_at: DateTime<Utc>,
    /// Capability-defined bounded facts.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: JsonMap,
}

/// Point-in-time state supplied to the planner by registered capabilities.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ObservedStateV3 {
    /// Capture time for the whole observation bundle.
    pub captured_at: DateTime<Utc>,
    /// Canonical digest of the exact observation bundle.
    pub digest: Sha256Digest,
    /// Profile-step-keyed observations; repeated capabilities remain distinct.
    pub values: BTreeMap<ActionId, ObservedValueV3>,
}

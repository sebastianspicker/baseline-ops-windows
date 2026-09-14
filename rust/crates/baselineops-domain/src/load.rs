use std::{fs::File, io::Read, path::Path};

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{DomainError, DomainResult, PlanV3, ProfileV3};

mod bounds;

/// Bounds applied before decoding any untrusted JSON document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonLoadLimits {
    /// Maximum number of UTF-8 bytes in the full document.
    pub max_bytes: usize,
    /// Maximum container nesting depth.
    pub max_depth: usize,
    /// Maximum number of object members in any JSON object.
    pub max_object_entries: usize,
    /// Maximum number of elements in any JSON array.
    pub max_array_entries: usize,
    /// Maximum UTF-8 byte length of any string value or property name.
    pub max_string_bytes: usize,
    /// Maximum number of JSON values in the document.
    pub max_nodes: usize,
}

impl Default for JsonLoadLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_depth: 32,
            max_object_entries: 256,
            max_array_entries: 1024,
            max_string_bytes: 64 * 1024,
            max_nodes: 16 * 1024,
        }
    }
}

/// Decodes bounded UTF-8 JSON into a strict serde contract.
///
/// Types in this crate use `deny_unknown_fields`; callers should use a typed
/// target instead of `Value` so unrecognized fields remain rejected.
///
/// # Errors
///
/// Returns an error for size, UTF-8, JSON syntax, structural-bound, or typed-schema failures.
pub fn load_json<T: DeserializeOwned>(bytes: &[u8], limits: JsonLoadLimits) -> DomainResult<T> {
    if bytes.len() > limits.max_bytes {
        return Err(DomainError::LimitExceeded {
            limit_name: "document byte size",
            limit: limits.max_bytes,
        });
    }
    let text = std::str::from_utf8(bytes)?;
    let value: Value = serde_json::from_str(text)?;
    bounds::validate_json_bounds(&value, limits, 0, &mut 0)?;
    Ok(serde_json::from_value(value)?)
}

/// Reads and decodes bounded UTF-8 JSON from a file without accepting an
/// arbitrarily large document into memory.
///
/// # Errors
///
/// Returns an error for I/O, size, UTF-8, JSON syntax, structural-bound, or typed-schema failures.
pub fn load_json_file<T: DeserializeOwned>(
    path: impl AsRef<Path>,
    limits: JsonLoadLimits,
) -> DomainResult<T> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|source| DomainError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(limits.max_bytes.min(64 * 1024) + 1);
    let mut limited = file.take((limits.max_bytes as u64).saturating_add(1));
    limited
        .read_to_end(&mut bytes)
        .map_err(|source| DomainError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    load_json(&bytes, limits)
}

/// Loads and semantically validates a strict v3 profile.
///
/// # Errors
///
/// Returns an error when decoding or profile graph validation fails.
pub fn load_profile_json(bytes: &[u8], limits: JsonLoadLimits) -> DomainResult<ProfileV3> {
    let profile: ProfileV3 = load_json(bytes, limits)?;
    profile.validate()?;
    Ok(profile)
}

/// Loads a strict v4 plan and validates its internal consistency.
///
/// Host, tool, source, input, and state bindings need live context and are
/// intentionally checked by [`PlanV3::validate_against`](crate::PlanV3::validate_against).
///
/// # Errors
///
/// Returns an error when decoding or internal plan validation fails.
pub fn load_plan_json(bytes: &[u8], limits: JsonLoadLimits) -> DomainResult<PlanV3> {
    let value: Value = load_json(bytes, limits)?;
    if value.get("schema_version").and_then(Value::as_str) != Some("4.0") {
        return Err(DomainError::Validation("saved plan contract is obsolete or unsupported; regenerate the plan and approve its new digest".into()));
    }
    let plan: PlanV3 = serde_json::from_value(value)?;
    plan.validate_structure()?;
    Ok(plan)
}

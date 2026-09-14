use serde_json::{Map, Value};

use crate::{DomainError, DomainResult};

use super::JsonLoadLimits;

pub(super) fn validate_json_bounds(
    value: &Value,
    limits: JsonLoadLimits,
    depth: usize,
    nodes: &mut usize,
) -> DomainResult<()> {
    validate_node_count(limits, nodes)?;
    validate_depth(depth, limits)?;
    match value {
        Value::String(value) => validate_string(value, limits),
        Value::Array(values) => validate_array(values, limits, depth, nodes),
        Value::Object(values) => validate_object(values, limits, depth, nodes),
        _ => Ok(()),
    }
}

fn validate_node_count(limits: JsonLoadLimits, nodes: &mut usize) -> DomainResult<()> {
    *nodes += 1;
    if *nodes > limits.max_nodes {
        return Err(DomainError::LimitExceeded {
            limit_name: "JSON value count",
            limit: limits.max_nodes,
        });
    }
    Ok(())
}

fn validate_depth(depth: usize, limits: JsonLoadLimits) -> DomainResult<()> {
    if depth > limits.max_depth {
        return Err(DomainError::LimitExceeded {
            limit_name: "JSON nesting depth",
            limit: limits.max_depth,
        });
    }
    Ok(())
}

fn validate_string(value: &str, limits: JsonLoadLimits) -> DomainResult<()> {
    if value.len() > limits.max_string_bytes {
        return Err(DomainError::LimitExceeded {
            limit_name: "JSON string size",
            limit: limits.max_string_bytes,
        });
    }
    Ok(())
}

fn validate_array(
    values: &[Value],
    limits: JsonLoadLimits,
    depth: usize,
    nodes: &mut usize,
) -> DomainResult<()> {
    if values.len() > limits.max_array_entries {
        return Err(DomainError::LimitExceeded {
            limit_name: "JSON array entry count",
            limit: limits.max_array_entries,
        });
    }
    for item in values {
        validate_json_bounds(item, limits, depth + 1, nodes)?;
    }
    Ok(())
}

fn validate_object(
    values: &Map<String, Value>,
    limits: JsonLoadLimits,
    depth: usize,
    nodes: &mut usize,
) -> DomainResult<()> {
    if values.len() > limits.max_object_entries {
        return Err(DomainError::LimitExceeded {
            limit_name: "JSON object entry count",
            limit: limits.max_object_entries,
        });
    }
    for (key, item) in values {
        validate_property_name(key, limits)?;
        validate_json_bounds(item, limits, depth + 1, nodes)?;
    }
    Ok(())
}

fn validate_property_name(key: &str, limits: JsonLoadLimits) -> DomainResult<()> {
    if key.len() > limits.max_string_bytes {
        return Err(DomainError::LimitExceeded {
            limit_name: "JSON property name size",
            limit: limits.max_string_bytes,
        });
    }
    Ok(())
}

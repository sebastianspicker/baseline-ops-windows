use crate::Roots;
use anyhow::{Result, bail};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub(super) fn verify_closure_membership(
    roots: &Roots,
    id: &str,
    legacy_script: &str,
    sources: &[Value],
) -> Result<()> {
    let actual = sources
        .iter()
        .map(|source| source["path"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    if actual != expected_closure_paths(roots, legacy_script)? {
        bail!("oracle source closure companion binding drifted for {id}");
    }
    Ok(())
}

/// The source closure is the entry script followed by every capability-private
/// `scripts/internal/<stem>.*.ps1` file in ordinal file-name order.
fn expected_closure_paths(roots: &Roots, legacy_script: &str) -> Result<Vec<String>> {
    let stem = Path::new(legacy_script)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let prefix = format!("{stem}.");
    let mut companions = Vec::new();
    for entry in fs::read_dir(roots.repository.join("scripts/internal"))? {
        if let Some(name) = companion_name(&entry?, &prefix)? {
            companions.push(format!("scripts/internal/{name}"));
        }
    }
    companions.sort();
    let mut paths = vec![legacy_script.to_owned()];
    paths.extend(companions);
    Ok(paths)
}

fn companion_name(entry: &fs::DirEntry, prefix: &str) -> Result<Option<String>> {
    let Ok(name) = entry.file_name().into_string() else {
        return Ok(None);
    };
    let is_script = Path::new(&name)
        .extension()
        .is_some_and(|extension| extension == "ps1");
    let is_companion = entry.file_type()?.is_file() && name.starts_with(prefix) && is_script;
    Ok(is_companion.then_some(name))
}

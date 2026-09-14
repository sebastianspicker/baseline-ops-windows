use anyhow::{Context, Result, bail};
use baselineops_domain::{
    JsonLoadLimits, PlanV3, ProfileV3, Sha256Digest, SourceKind, canonical_json_digest, load_json,
};

pub(super) fn load_profile_source(plan: &PlanV3) -> Result<String> {
    let canonical = canonical_source_path(plan)?;
    let source = baselineops_windows::read_bounded_utf8_no_follow(
        &canonical,
        baselineops_windows::MAX_INPUT_BYTES,
    )?;
    validate_profile_source(plan, &source)?;
    Ok(source)
}

fn canonical_source_path(plan: &PlanV3) -> Result<std::path::PathBuf> {
    if plan.source.kind != SourceKind::LocalFile {
        bail!("apply accepts only a locally validated profile source");
    }
    let path = std::path::PathBuf::from(&plan.source.locator);
    if !path.is_absolute() {
        bail!("profile source must use an absolute canonical path");
    }
    let parent = path
        .parent()
        .context("profile source has no parent directory")?;
    baselineops_windows::PathPolicy::new(parent)?
        .existing_file(&path)
        .map_err(Into::into)
}

fn validate_profile_source(plan: &PlanV3, source: &str) -> Result<()> {
    if Sha256Digest::of_bytes(source.as_bytes()) != plan.source.digest {
        bail!("profile source digest changed since the plan was created");
    }
    let profile: ProfileV3 = load_json(source.as_bytes(), JsonLoadLimits::default())?;
    profile.validate()?;
    if canonical_json_digest(&profile)? != plan.profile_digest || profile.id != plan.profile_id {
        bail!("profile source no longer matches the reviewed plan identity");
    }
    Ok(())
}

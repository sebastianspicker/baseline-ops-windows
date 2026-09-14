use super::*;
use baselineops_domain::{
    ActionId, CapabilityId, JsonMap, ProfileDefaultsV3, ProfileId, SchemaVersion,
};

struct EchoParameters;
impl TrustedObservationSource for EchoParameters {
    fn observe(&self, step: &ProfileStepV3) -> Result<serde_json::Value, String> {
        serde_json::to_value(&step.parameters).map_err(|error| error.to_string())
    }
}

#[test]
fn repeated_capabilities_retain_each_steps_parameters_and_facts() {
    let first = ProfileStepV3 {
        step_id: ActionId::new(),
        capability_id: CapabilityId::new("v3.test.repeated").unwrap(),
        parameters: JsonMap::from([("value".into(), serde_json::json!(1))]),
        depends_on: vec![],
        continue_on_error: false,
    };
    let second = ProfileStepV3 {
        step_id: ActionId::new(),
        parameters: JsonMap::from([("value".into(), serde_json::json!(2))]),
        ..first.clone()
    };
    let profile = ProfileV3 {
        schema_version: SchemaVersion::V3,
        id: ProfileId::new(),
        name: "repeated".into(),
        version: "1".into(),
        description: None,
        created_at: Utc::now(),
        expires_at: None,
        defaults: ProfileDefaultsV3::default(),
        steps: vec![first.clone(), second.clone()],
        metadata: JsonMap::new(),
    };
    let observed = reobserve_profile(&profile, &EchoParameters, Utc::now()).unwrap();
    assert_eq!(observed.values.len(), 2);
    assert_ne!(
        observed.values[&first.step_id].parameters_digest,
        observed.values[&second.step_id].parameters_digest
    );
    assert_eq!(
        observed.values[&first.step_id].facts["native_result"]["value"],
        1
    );
    assert_eq!(
        observed.values[&second.step_id].facts["native_result"]["value"],
        2
    );
    let mut swapped = observed.clone();
    let a = swapped.values[&first.step_id].clone();
    let b = swapped.values[&second.step_id].clone();
    swapped.values.insert(first.step_id, b);
    swapped.values.insert(second.step_id, a);
    assert_ne!(observed.digest, swapped.calculated_digest().unwrap());
}

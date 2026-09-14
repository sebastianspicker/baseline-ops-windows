//! Opt-in portable scheduler preparation measurements, with deterministic inputs.

use super::*;
use baselineops_domain::{CapabilityId, RebootRequirement, Reversibility, RiskLevel};
use std::{collections::BTreeSet, hint::black_box, time::Instant};

fn workload(count: usize, shape: &str) -> Vec<PlannedActionV3> {
    let id = |index: usize| ActionId::from(uuid::Uuid::from_u128((index + 1) as u128));
    (0..count)
        .map(|index| PlannedActionV3 {
            id: id(index),
            source_step: id(index),
            capability: CapabilityId::new("v3.test.benchmark").unwrap(),
            operation: Operation::Audit,
            parameters: JsonMap::new(),
            depends_on: match shape {
                "chain" if index > 0 => vec![id(index - 1)],
                "layered" if index >= 8 => ((index / 8 - 1) * 8..index / 8 * 8).map(id).collect(),
                _ => vec![],
            },
            continue_on_error: false,
            facts_digest: baselineops_domain::Sha256Digest::of_bytes([]),
            preconditions: vec![],
            risk: RiskLevel::Low,
            reversibility: Reversibility::NotApplicable,
            reboot: RebootRequirement::NotRequired,
            privileges: vec![],
            metadata: JsonMap::new(),
        })
        .rev()
        .collect()
}

#[test]
#[ignore = "portable timing harness; run --release --ignored --nocapture"]
fn scheduler_preparation_distribution() {
    for count in [32, 256, 1024] {
        for shape in ["independent", "chain", "layered"] {
            compare_workload(count, shape);
        }
    }
}

type Orderer = fn(&[PlannedActionV3]) -> Result<Vec<ActionId>, SchedulerError>;
fn compare_workload(count: usize, shape: &str) {
    let actions = workload(count, shape);
    let expected = reference_order(&actions).unwrap();
    for _ in 0..10 {
        black_box(reference_order(black_box(&actions)).unwrap());
        black_box(topological_order(black_box(&actions)).unwrap());
    }
    let mut reference = Vec::with_capacity(100);
    let mut indexed = Vec::with_capacity(100);
    for sample in 0..100 {
        // Alternate which algorithm runs first, within the same process/workload.
        let orderers: [Orderer; 2] = if sample % 2 == 0 {
            [reference_order, topological_order]
        } else {
            [topological_order, reference_order]
        };
        let first = measure(orderers[0], &actions, &expected);
        let second = measure(orderers[1], &actions, &expected);
        let (before, after) = if sample % 2 == 0 {
            (first, second)
        } else {
            (second, first)
        };
        reference.push(before);
        indexed.push(after);
    }
    distribution("reference", shape, count, reference);
    distribution("indexed", shape, count, indexed);
}

fn measure(orderer: Orderer, actions: &[PlannedActionV3], expected: &[ActionId]) -> u128 {
    let start = Instant::now();
    let result = orderer(black_box(actions)).unwrap();
    let elapsed = start.elapsed().as_nanos();
    assert_eq!(result, expected);
    elapsed
}

fn distribution(algorithm: &str, shape: &str, count: usize, mut samples: Vec<u128>) {
    samples.sort_unstable();
    println!(
        "scheduler_prepare,{algorithm},{shape},{count},samples=100,p50_ns={},p95_ns={},p99_ns={}",
        samples[49], samples[94], samples[98]
    );
}

// Frozen pre-indexing implementation used only as a behavior and timing oracle.
pub(super) fn reference_order(
    actions: &[PlannedActionV3],
) -> Result<Vec<ActionId>, SchedulerError> {
    if actions.is_empty() {
        return Err(SchedulerError::InvalidGraph(
            "no actions were supplied".into(),
        ));
    }
    let by_id = actions
        .iter()
        .map(|action| (action.id, action))
        .collect::<BTreeMap<_, _>>();
    if by_id.len() != actions.len() {
        return Err(SchedulerError::InvalidGraph("duplicate action IDs".into()));
    }
    let mut complete = BTreeSet::new();
    let mut order = Vec::with_capacity(actions.len());
    while order.len() < actions.len() {
        let next = actions.iter().find(|action| {
            !complete.contains(&action.id)
                && action
                    .depends_on
                    .iter()
                    .all(|dependency| complete.contains(dependency))
        });
        let Some(next) = next else {
            return Err(SchedulerError::InvalidGraph(
                "dependencies are missing or cyclic".into(),
            ));
        };
        if next
            .depends_on
            .iter()
            .any(|dependency| !by_id.contains_key(dependency))
        {
            return Err(SchedulerError::InvalidGraph(
                "an action depends on an unknown action".into(),
            ));
        }
        complete.insert(next.id);
        order.push(next.id);
    }
    Ok(order)
}

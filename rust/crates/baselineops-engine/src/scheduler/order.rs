//! Dependency-indexed preparation preserving the first-ready input-order contract.

use super::{ActionId, PlannedActionV3, SchedulerError};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn topological_order(
    actions: &[PlannedActionV3],
) -> Result<Vec<ActionId>, SchedulerError> {
    let by_id = action_positions(actions)?;
    let mut graph = DependencyIndex::build(actions, &by_id)?;
    let mut ready: BTreeSet<_> = graph
        .pending
        .iter()
        .enumerate()
        .filter_map(|(position, count)| (*count == 0).then_some(position))
        .collect();
    let mut order = Vec::with_capacity(actions.len());
    while let Some(position) = ready.pop_first() {
        order.push(actions[position].id);
        graph.complete(position, &mut ready);
    }
    if order.len() != actions.len() {
        return Err(incomplete_graph());
    }
    Ok(order)
}

fn action_positions(
    actions: &[PlannedActionV3],
) -> Result<BTreeMap<ActionId, usize>, SchedulerError> {
    if actions.is_empty() {
        return Err(SchedulerError::InvalidGraph(
            "no actions were supplied".into(),
        ));
    }
    let positions: BTreeMap<_, _> = actions
        .iter()
        .enumerate()
        .map(|(position, action)| (action.id, position))
        .collect();
    if positions.len() != actions.len() {
        return Err(SchedulerError::InvalidGraph("duplicate action IDs".into()));
    }
    Ok(positions)
}

struct DependencyIndex {
    pending: Vec<usize>,
    dependents: Vec<Vec<usize>>,
}

impl DependencyIndex {
    fn build(
        actions: &[PlannedActionV3],
        positions: &BTreeMap<ActionId, usize>,
    ) -> Result<Self, SchedulerError> {
        let mut index = Self {
            pending: actions
                .iter()
                .map(|action| action.depends_on.len())
                .collect(),
            dependents: vec![Vec::new(); actions.len()],
        };
        for (position, action) in actions.iter().enumerate() {
            for dependency in &action.depends_on {
                let parent = positions.get(dependency).ok_or_else(incomplete_graph)?;
                index.dependents[*parent].push(position);
            }
        }
        Ok(index)
    }

    fn complete(&mut self, position: usize, ready: &mut BTreeSet<usize>) {
        for dependent in &self.dependents[position] {
            // Duplicate edges retain their multiplicity, and are discharged once
            // per edge; the original all-dependencies check accepts them too.
            self.pending[*dependent] -= 1;
            if self.pending[*dependent] == 0 {
                ready.insert(*dependent);
            }
        }
    }
}

fn incomplete_graph() -> SchedulerError {
    SchedulerError::InvalidGraph("dependencies are missing or cyclic".into())
}

#[cfg(test)]
mod tests;

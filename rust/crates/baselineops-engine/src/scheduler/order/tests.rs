use super::*;
use crate::scheduler::{bench::reference_order, tests::action};

fn assert_same(actions: &[PlannedActionV3]) {
    assert_eq!(
        topological_order(actions).map_err(|error| error.to_string()),
        reference_order(actions).map_err(|error| error.to_string())
    );
}

#[test]
fn all_four_node_dags_and_input_permutations_preserve_first_ready_order() {
    let nodes: Vec<_> = (0..4).map(|_| action(vec![], false)).collect();
    for edges in 0..64 {
        let mut graph = nodes.clone();
        let mut bit = 0;
        for (child, action) in graph.iter_mut().enumerate().skip(1) {
            for parent in nodes.iter().take(child) {
                if edges & (1 << bit) != 0 {
                    action.depends_on.push(parent.id);
                }
                bit += 1;
            }
        }
        check_permutations(&mut graph, 0);
    }
}

fn check_permutations(graph: &mut [PlannedActionV3], offset: usize) {
    if offset == graph.len() {
        assert_same(graph);
        return;
    }
    for next in offset..graph.len() {
        graph.swap(offset, next);
        check_permutations(graph, offset + 1);
        graph.swap(offset, next);
    }
}

#[test]
fn malformed_graphs_preserve_error_text_and_precedence() {
    assert_same(&[]);
    let mut first = action(vec![], false);
    assert_same(&[first.clone(), first.clone()]);
    first.depends_on.push(ActionId::new());
    assert_same(&[first.clone()]);
    assert_same(&[first.clone(), first.clone()]);
    first.depends_on = vec![first.id];
    assert_same(&[first.clone()]);
    let second = action(vec![first.id], false);
    first.depends_on = vec![second.id];
    assert_same(&[action(vec![], false), first, second]);
}

#[test]
fn duplicate_edges_and_newly_ready_earlier_actions_preserve_order() {
    let first = action(vec![], false);
    let second = action(vec![first.id, first.id], false);
    let unrelated = action(vec![], false);
    let graph = [second.clone(), first.clone(), unrelated.clone()];
    assert_eq!(
        topological_order(&graph).unwrap(),
        vec![first.id, second.id, unrelated.id]
    );
    assert_same(&graph);
}

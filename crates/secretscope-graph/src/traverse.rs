//! Blast-radius traversal.
//!
//! Because the builder only creates reachable nodes, "what can this principal
//! reach" is just "every resource node in the graph". Breadth-first search is
//! used for one thing: reconstructing a representative shortest path to each
//! resource by following parent pointers back to the start. BFS gives the
//! fewest-hops path, and because edges are added in a deterministic order the
//! chosen path is stable across runs.

use crate::graph::{NodeKind, PermissionGraph, Relation};
use crate::render::render_tree;
use crate::types::{BlastRadius, ResourceReach, Step};
use secretscope_iam::Account;
use std::collections::VecDeque;

/// Analyze a compromised principal. Returns `None` if the principal is unknown.
pub fn analyze(account: &Account, principal: &str) -> Option<BlastRadius> {
    let graph = PermissionGraph::build(account, principal)?;
    Some(assemble(&graph, account, principal))
}

/// Analyze and also return a rendered ASCII tree of the graph.
pub fn analyze_with_tree(account: &Account, principal: &str) -> Option<(BlastRadius, String)> {
    let graph = PermissionGraph::build(account, principal)?;
    let tree = render_tree(&graph);
    Some((assemble(&graph, account, principal), tree))
}

/// BFS parent pointers from the start node.
fn parents(graph: &PermissionGraph) -> Vec<Option<usize>> {
    let mut parent = vec![None; graph.node_count()];
    let mut seen = vec![false; graph.node_count()];
    let mut queue = VecDeque::new();
    let start = graph.start();
    seen[start] = true;
    queue.push_back(start);
    while let Some(cur) = queue.pop_front() {
        for &(next, _rel) in graph.neighbors(cur) {
            if !seen[next] {
                seen[next] = true;
                parent[next] = Some(cur);
                queue.push_back(next);
            }
        }
    }
    parent
}

fn path_to(graph: &PermissionGraph, parent: &[Option<usize>], target: usize) -> Vec<Step> {
    let mut ids = Vec::new();
    let mut cur = Some(target);
    while let Some(id) = cur {
        ids.push(id);
        cur = parent[id];
    }
    ids.reverse();
    ids.into_iter()
        .map(|id| {
            let n = graph.node(id);
            match n.kind {
                NodeKind::Principal => Step::Principal(n.label.clone()),
                NodeKind::Policy => Step::Policy(n.label.clone()),
                NodeKind::Action => Step::Action(n.label.clone()),
                NodeKind::Resource => Step::Resource(n.label.clone()),
            }
        })
        .collect()
}

fn assemble(graph: &PermissionGraph, account: &Account, principal: &str) -> BlastRadius {
    let parent = parents(graph);

    let mut resources: Vec<ResourceReach> = Vec::new();
    for res_id in graph.resource_node_ids() {
        let arn = graph.node(res_id).label.clone();

        // Every action node that can access this resource.
        let mut actions: Vec<String> = Vec::new();
        for id in 0..graph.node_count() {
            if graph.node(id).kind != NodeKind::Action {
                continue;
            }
            for &(to, rel) in graph.neighbors(id) {
                if to == res_id && rel == Relation::CanAccess {
                    actions.push(graph.node(id).label.clone());
                }
            }
        }
        actions.sort();
        actions.dedup();

        let path = path_to(graph, &parent, res_id);
        let principal_steps = path
            .iter()
            .filter(|s| matches!(s, Step::Principal(_)))
            .count();

        // Metadata comes from the account fixture where available.
        let meta = account.resources.iter().find(|r| r.arn == arn);
        let (service, environment, sensitive) = match meta {
            Some(m) => (m.service.clone(), m.environment.clone(), m.sensitive),
            None => (String::new(), String::new(), false),
        };

        resources.push(ResourceReach {
            arn,
            service,
            environment,
            sensitive,
            actions,
            via_assumed_role: principal_steps > 1,
            path,
        });
    }

    resources.sort_by(|a, b| a.arn.cmp(&b.arn));
    let assumed_roles = graph.assumed_role_names();

    BlastRadius {
        principal: principal.to_string(),
        reachable_count: resources.len(),
        privilege_paths: assumed_roles.len(),
        assumed_roles,
        resources,
    }
}

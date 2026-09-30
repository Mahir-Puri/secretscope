//! Building the permission graph.
//!
//! I chose a small hand-written graph rather than a general graph library. The
//! model has four node kinds and four edge kinds, and the operations I need
//! (build, breadth-first traversal, parent-pointer path reconstruction, an
//! ASCII tree) are short enough that a dependency would add surface area
//! without making anything clearer.
//!
//! Node identity rules keep reconstructed paths clean:
//! - Principal and Resource nodes are shared (deduplicated by name / ARN). A
//!   role reached twice is the same node, which is how cycles close.
//! - Policy and Action nodes are created fresh per grant, so a path never
//!   accidentally routes through an unrelated policy.
//!
//! The builder only ever expands identities it can actually reach: it starts at
//! the compromised principal and follows allowed `sts:AssumeRole` edges, with a
//! visited set of principal names so a cycle such as A -> B -> C -> A ends. As a
//! result every node in the finished graph is reachable from the start, which
//! makes later analysis simple.

use secretscope_iam::{evaluate, glob_match, Account, Decision, ACTION_VOCABULARY};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Principal,
    Policy,
    Action,
    Resource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    HasPolicy,
    Allows,
    CanAssume,
    CanAccess,
}

#[derive(Debug, Clone)]
pub struct GraphNode {
    pub kind: NodeKind,
    pub label: String,
}

/// A permission graph rooted at one compromised principal.
#[derive(Debug, Clone)]
pub struct PermissionGraph {
    nodes: Vec<GraphNode>,
    adj: Vec<Vec<(usize, Relation)>>,
    start: usize,
    principal_ids: HashMap<String, usize>,
    resource_ids: HashMap<String, usize>,
    grant_guard: HashSet<(usize, String, String)>,
}

impl PermissionGraph {
    fn new() -> Self {
        PermissionGraph {
            nodes: Vec::new(),
            adj: Vec::new(),
            start: 0,
            principal_ids: HashMap::new(),
            resource_ids: HashMap::new(),
            grant_guard: HashSet::new(),
        }
    }

    fn add_node(&mut self, kind: NodeKind, label: &str) -> usize {
        let id = self.nodes.len();
        self.nodes.push(GraphNode {
            kind,
            label: label.to_string(),
        });
        self.adj.push(Vec::new());
        id
    }

    fn principal_node(&mut self, name: &str) -> usize {
        if let Some(&id) = self.principal_ids.get(name) {
            return id;
        }
        let id = self.add_node(NodeKind::Principal, name);
        self.principal_ids.insert(name.to_string(), id);
        id
    }

    fn resource_node(&mut self, arn: &str) -> usize {
        if let Some(&id) = self.resource_ids.get(arn) {
            return id;
        }
        let id = self.add_node(NodeKind::Resource, arn);
        self.resource_ids.insert(arn.to_string(), id);
        id
    }

    fn add_edge(&mut self, from: usize, to: usize, rel: Relation) {
        self.adj[from].push((to, rel));
    }

    /// Build the graph for `start_principal`. Returns `None` if that principal
    /// is not present in the account.
    pub fn build(account: &Account, start_principal: &str) -> Option<Self> {
        account.principal_by_name(start_principal)?;

        let mut g = PermissionGraph::new();
        g.start = g.principal_node(start_principal);

        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        queue.push_back(start_principal.to_string());

        while let Some(pname) = queue.pop_front() {
            if !visited.insert(pname.clone()) {
                continue;
            }
            let principal = match account.principal_by_name(&pname) {
                Some(p) => p,
                None => continue,
            };
            let pid = g.principal_node(&pname);
            let all_policies = account.resolve_policies(principal.policy_names());

            for policy_name in principal.policy_names() {
                let policy = match account.policy_by_name(policy_name) {
                    Some(p) => p,
                    None => continue,
                };
                let pol_id = g.add_node(NodeKind::Policy, policy_name);
                g.add_edge(pid, pol_id, Relation::HasPolicy);

                for stmt in &policy.statements {
                    if !matches!(stmt.effect, secretscope_iam::Effect::Allow) {
                        continue;
                    }
                    for action_pattern in &stmt.actions {
                        // Role assumption edges.
                        if glob_match(action_pattern, "sts:AssumeRole") {
                            let mut roles: Vec<_> = account
                                .roles
                                .iter()
                                .filter(|r| stmt.resources.iter().any(|rp| glob_match(rp, &r.arn)))
                                .collect();
                            roles.sort_by(|a, b| a.arn.cmp(&b.arn));
                            for role in roles {
                                if evaluate(&all_policies, "sts:AssumeRole", &role.arn)
                                    != Decision::Allowed
                                {
                                    continue;
                                }
                                let key = (pol_id, "sts:AssumeRole".to_string(), role.arn.clone());
                                if !g.grant_guard.insert(key) {
                                    continue;
                                }
                                let act_id = g.add_node(NodeKind::Action, "sts:AssumeRole");
                                g.add_edge(pol_id, act_id, Relation::Allows);
                                let role_pid = g.principal_node(&role.name);
                                g.add_edge(act_id, role_pid, Relation::CanAssume);
                                queue.push_back(role.name.clone());
                            }
                        }

                        // Resource access edges.
                        let mut resources: Vec<_> = account.resources.iter().collect();
                        resources.sort_by(|a, b| a.arn.cmp(&b.arn));
                        for action in ACTION_VOCABULARY
                            .iter()
                            .filter(|a| **a != "sts:AssumeRole")
                            .filter(|a| glob_match(action_pattern, a))
                        {
                            for res in &resources {
                                if !stmt.resources.iter().any(|rp| glob_match(rp, &res.arn)) {
                                    continue;
                                }
                                if evaluate(&all_policies, action, &res.arn) != Decision::Allowed {
                                    continue;
                                }
                                let key = (pol_id, action.to_string(), res.arn.clone());
                                if !g.grant_guard.insert(key) {
                                    continue;
                                }
                                let act_id = g.add_node(NodeKind::Action, action);
                                g.add_edge(pol_id, act_id, Relation::Allows);
                                let res_id = g.resource_node(&res.arn);
                                g.add_edge(act_id, res_id, Relation::CanAccess);
                            }
                        }
                    }
                }
            }
        }

        Some(g)
    }

    // ---- read-only accessors used by traversal and rendering ----

    pub fn start(&self) -> usize {
        self.start
    }
    pub fn node(&self, id: usize) -> &GraphNode {
        &self.nodes[id]
    }
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
    pub fn neighbors(&self, id: usize) -> &[(usize, Relation)] {
        &self.adj[id]
    }
    pub fn resource_node_ids(&self) -> Vec<usize> {
        let mut ids: Vec<usize> = self.resource_ids.values().copied().collect();
        ids.sort();
        ids
    }
    /// Principal nodes other than the start node, i.e. assumed roles.
    pub fn assumed_role_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .principal_ids
            .iter()
            .filter(|(_, &id)| id != self.start)
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names
    }
}

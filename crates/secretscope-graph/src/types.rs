//! Shared result types produced by blast-radius analysis.

use serde::{Deserialize, Serialize};

/// One node in a reconstructed path. Rendered as
/// `principal -> policy -> action -> ... -> resource`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum Step {
    Principal(String),
    Policy(String),
    Action(String),
    Resource(String),
}

impl Step {
    pub fn name(&self) -> &str {
        match self {
            Step::Principal(s) | Step::Policy(s) | Step::Action(s) | Step::Resource(s) => s,
        }
    }
}

/// Render a path as a single readable line.
pub fn render_path(path: &[Step]) -> String {
    path.iter()
        .map(|s| s.name().to_string())
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// A resource that the compromised principal can reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceReach {
    pub arn: String,
    pub service: String,
    pub environment: String,
    pub sensitive: bool,
    /// Vocabulary actions allowed on this resource across every reachable identity.
    pub actions: Vec<String>,
    /// True when reaching this resource required assuming at least one role.
    pub via_assumed_role: bool,
    /// A representative shortest path from the start principal to this resource.
    pub path: Vec<Step>,
}

/// The full result of analyzing one compromised principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlastRadius {
    pub principal: String,
    pub resources: Vec<ResourceReach>,
    pub assumed_roles: Vec<String>,
    pub reachable_count: usize,
    /// Number of assume-role privilege paths discovered (one per assumed role).
    pub privilege_paths: usize,
}

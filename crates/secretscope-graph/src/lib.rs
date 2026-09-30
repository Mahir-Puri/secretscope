//! SecretScope permission graph and blast-radius analysis.
//!
//! Given a loaded IAM account and a compromised principal, this crate builds a
//! permission graph, follows allowed role assumption, and reports which
//! resources become reachable and by what path. Cycles in role assumption are
//! handled with a visited set so traversal always terminates.

mod graph;
mod render;
mod traverse;
mod types;

pub use graph::{GraphNode, NodeKind, PermissionGraph, Relation};
pub use render::render_tree;
pub use traverse::{analyze, analyze_with_tree};
pub use types::{render_path, BlastRadius, ResourceReach, Step};

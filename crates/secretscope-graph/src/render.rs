//! ASCII tree rendering of a permission graph.
//!
//! This produces the indented `blast radius` view shown in the CLI. It walks
//! the graph from the start principal. A principal is only expanded once; if a
//! role is reached again through a cycle it is printed with a `(cycle)` marker
//! instead of being expanded a second time, so the output is always finite.

use crate::graph::{NodeKind, PermissionGraph};
use std::collections::HashSet;

/// Render the graph rooted at its start node as an indented tree.
pub fn render_tree(graph: &PermissionGraph) -> String {
    let mut out = String::new();
    let start = graph.start();
    out.push_str(graph.node(start).label.as_str());
    out.push('\n');
    let mut expanded: HashSet<usize> = HashSet::new();
    expanded.insert(start);
    walk(graph, start, "", &mut expanded, &mut out);
    out.trim_end().to_string()
}

fn walk(
    graph: &PermissionGraph,
    node: usize,
    prefix: &str,
    expanded: &mut HashSet<usize>,
    out: &mut String,
) {
    let children = graph.neighbors(node);
    let count = children.len();
    for (i, &(child, _rel)) in children.iter().enumerate() {
        let last = i + 1 == count;
        let branch = if last { "\\-- " } else { "|-- " };
        let node_ref = graph.node(child);

        // A principal reached a second time is a cycle; mark and do not expand.
        let is_principal = node_ref.kind == NodeKind::Principal;
        let already = is_principal && expanded.contains(&child);
        let suffix = if already { " (cycle)" } else { "" };

        out.push_str(prefix);
        out.push_str(branch);
        out.push_str(&node_ref.label);
        out.push_str(suffix);
        out.push('\n');

        if already {
            continue;
        }
        if is_principal {
            expanded.insert(child);
        }
        let child_prefix = format!("{prefix}{}", if last { "    " } else { "|   " });
        walk(graph, child, &child_prefix, expanded, out);
    }
}

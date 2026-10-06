//! Rendering findings as text or JSON.
//!
//! Both renderers work from the same analyzed data and neither can emit a raw
//! secret: the only credential-derived value carried this far is the short
//! fingerprint prefix. A test in `tests/` asserts that the raw key string never
//! appears in JSON output.

use crate::run::AnalyzedFinding;
use secretscope_graph::{render_path, ResourceReach};
use secretscope_risk::Severity;
use serde::Serialize;

pub struct Meta {
    pub root: String,
    pub history: bool,
}

// ---------------- JSON ----------------

#[derive(Serialize)]
struct JsonScan {
    root: String,
    findings: usize,
    history: bool,
    max_severity: Option<String>,
}

#[derive(Serialize)]
struct JsonFinding {
    credential_type: String,
    location: String,
    path: String,
    line: usize,
    fingerprint: String,
    principal: Option<String>,
    severity: String,
    score: u32,
    reasons: Vec<String>,
    reachable_resources: Vec<ResourceReach>,
    assumed_roles: Vec<String>,
    privilege_paths: usize,
    paths: Vec<String>,
}

#[derive(Serialize)]
struct JsonReport {
    scan: JsonScan,
    findings: Vec<JsonFinding>,
}

fn max_severity(items: &[AnalyzedFinding]) -> Option<Severity> {
    items.iter().map(|a| a.risk.severity).max()
}

pub fn render_json(items: &[AnalyzedFinding], meta: &Meta) -> String {
    let findings: Vec<JsonFinding> = items
        .iter()
        .map(|a| {
            let (resources, roles, priv_paths) = match &a.blast {
                Some(b) => (
                    b.resources.clone(),
                    b.assumed_roles.clone(),
                    b.privilege_paths,
                ),
                None => (Vec::new(), Vec::new(), 0),
            };
            let paths = resources.iter().map(|r| render_path(&r.path)).collect();
            JsonFinding {
                credential_type: serde_json::to_value(a.finding.kind)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_default(),
                location: a.finding.location(),
                path: a.finding.path.clone(),
                line: a.finding.line,
                fingerprint: a.finding.fingerprint_prefix.clone(),
                principal: a.principal.clone(),
                severity: a.risk.severity.as_str().to_lowercase(),
                score: a.risk.score,
                reasons: a.risk.reasons.clone(),
                reachable_resources: resources,
                assumed_roles: roles,
                privilege_paths: priv_paths,
                paths,
            }
        })
        .collect();

    let report = JsonReport {
        scan: JsonScan {
            root: meta.root.clone(),
            findings: items.len(),
            history: meta.history,
            max_severity: max_severity(items).map(|s| s.as_str().to_lowercase()),
        },
        findings,
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

// ---------------- Text ----------------

struct Paint {
    enabled: bool,
}
impl Paint {
    fn sev(&self, s: Severity) -> String {
        if !self.enabled {
            return format!("[{}]", s.as_str());
        }
        let code = match s {
            Severity::Low => "36",      // cyan
            Severity::Medium => "33",   // yellow
            Severity::High => "35",     // magenta
            Severity::Critical => "31", // red
        };
        format!("\x1b[1;{code}m[{}]\x1b[0m", s.as_str())
    }
}

pub fn render_text(items: &[AnalyzedFinding], meta: &Meta, color: bool) -> String {
    let paint = Paint { enabled: color };
    let mut out = String::new();
    out.push_str("SecretScope\n\n");
    out.push_str(&format!("Scanned: {}\n", meta.root));
    out.push_str(&format!("Findings: {}\n", items.len()));
    if meta.history {
        out.push_str("History: included\n");
    }
    out.push('\n');

    if items.is_empty() {
        out.push_str("No credentials detected.\n");
        return out;
    }

    for a in items {
        out.push_str(&format!(
            "{} {}\n",
            paint.sev(a.risk.severity),
            a.finding.kind.label()
        ));
        out.push_str(&format!("Location: {}\n", a.finding.location()));
        if let secretscope_scanner::Origin::GitHistory { commit } = &a.finding.origin {
            out.push_str(&format!("Commit: {}\n", &commit[..commit.len().min(12)]));
        }
        out.push_str(&format!("Redacted: {}\n", a.finding.redacted));
        out.push_str(&format!("Fingerprint: {}\n", a.finding.fingerprint_prefix));

        match &a.principal {
            Some(p) => out.push_str(&format!("Identity: {p}\n")),
            None => {
                out.push_str("Identity: unknown\n");
                out.push_str(
                    "Blast-radius analysis unavailable: no matching IAM identity was provided.\n",
                );
            }
        }

        if let Some(tree) = &a.tree {
            out.push_str("\nBlast radius:\n");
            out.push_str(tree);
            out.push('\n');
        }
        if let Some(b) = &a.blast {
            out.push_str(&format!(
                "\nReachable resources: {}\nPrivilege paths: {}\n",
                b.reachable_count, b.privilege_paths
            ));
        }

        out.push_str(&format!(
            "\nRisk: {} (score {})\n",
            a.risk.severity.as_str(),
            a.risk.score
        ));
        out.push_str("Reasons:\n");
        for reason in &a.risk.reasons {
            out.push_str(&format!("- {reason}\n"));
        }
        out.push_str("\n----\n\n");
    }

    out.trim_end().to_string()
}

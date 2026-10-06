//! Deterministic risk scoring.
//!
//! The score is a sum of points from a fixed set of rules. Every rule that
//! fires also adds a plain-language reason, and the reasons are what a user
//! should read first. The numeric score exists only to pick a severity band and
//! is shown as a secondary detail. Nothing here is learned or random; the same
//! input always produces the same output.
//!
//! Scoring rules (points):
//! - a credential was detected: +1 (always, this is the baseline)
//! - the credential maps to a known IAM identity: +1
//! - read access to a reachable resource: +1
//! - ability to invoke a function: +1
//! - write access to a reachable resource: +2
//! - delete access to a reachable resource: +2
//! - access to a secret value: +3
//! - a role can be assumed (a privilege path exists): +3
//! - a production or sensitive resource is reachable: +3
//! - three or more resources are reachable (breadth): +1
//!
//! Severity bands by total score:
//! - 0 to 2: LOW
//! - 3 to 5: MEDIUM
//! - 6 to 9: HIGH
//! - 10 or more: CRITICAL

use crate::severity::Severity;
use secretscope_graph::BlastRadius;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub severity: Severity,
    /// Internal numeric score. Secondary to `reasons`.
    pub score: u32,
    pub reasons: Vec<String>,
}

fn band(score: u32) -> Severity {
    match score {
        0..=2 => Severity::Low,
        3..=5 => Severity::Medium,
        6..=9 => Severity::High,
        _ => Severity::Critical,
    }
}

/// Assess risk for one finding.
///
/// `mapped` is whether the credential's fingerprint matched an IAM identity.
/// `blast` is the blast radius for that identity, or `None` when the credential
/// could not be mapped.
pub fn assess(mapped: bool, blast: Option<&BlastRadius>) -> RiskAssessment {
    let mut score = 0u32;
    let mut reasons: Vec<String> = Vec::new();

    // Baseline: something that looks like a credential was found.
    score += 1;
    reasons.push("a credential was detected in the repository".to_string());

    let blast = match blast {
        Some(b) if mapped => b,
        _ => {
            reasons.push(
                "no IAM identity was matched, so blast radius could not be computed".to_string(),
            );
            return RiskAssessment {
                severity: band(score),
                score,
                reasons,
            };
        }
    };

    score += 1;
    reasons.push(format!(
        "credential maps to the IAM identity {}",
        blast.principal
    ));

    // Aggregate capabilities across every reachable resource.
    let mut read = false;
    let mut write = false;
    let mut delete = false;
    let mut secret = false;
    let mut invoke = false;
    let mut production = false;

    for res in &blast.resources {
        if res.actions.is_empty() {
            continue;
        }
        for action in &res.actions {
            match action.as_str() {
                "s3:GetObject" => read = true,
                "s3:PutObject" => write = true,
                "s3:DeleteObject" => delete = true,
                "secretsmanager:GetSecretValue" => secret = true,
                "lambda:InvokeFunction" => invoke = true,
                _ => {}
            }
        }
        if res.sensitive || res.environment.eq_ignore_ascii_case("production") {
            production = true;
        }
    }

    // Order matters only for readability: strongest signals first.
    if !blast.assumed_roles.is_empty() {
        score += 3;
        reasons.push(format!(
            "credential can assume {} role(s), creating a privilege path",
            blast.assumed_roles.len()
        ));
    }
    if secret {
        score += 3;
        reasons.push("reachable identity can retrieve a secret value".to_string());
    }
    if production {
        score += 3;
        reasons.push("a production or sensitive resource is reachable".to_string());
    }
    if delete {
        score += 2;
        reasons.push("reachable identity can delete objects".to_string());
    }
    if write {
        score += 2;
        reasons.push("reachable identity can write to a resource".to_string());
    }
    if invoke {
        score += 1;
        reasons.push("reachable identity can invoke a function".to_string());
    }
    if read {
        score += 1;
        reasons.push("reachable identity can read a resource".to_string());
    }
    if blast.reachable_count >= 3 {
        score += 1;
        reasons.push(format!(
            "{} resources are reachable in total",
            blast.reachable_count
        ));
    }

    if blast.resources.is_empty() {
        reasons.push("no reachable resources were found for this identity".to_string());
    }

    RiskAssessment {
        severity: band(score),
        score,
        reasons,
    }
}

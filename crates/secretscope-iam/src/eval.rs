//! Permission evaluation.
//!
//! The rule that matters most: an explicit `Deny` always beats an `Allow`. To
//! decide whether an action on a resource is permitted we look at every
//! statement in the principal's policies. If any matching statement denies, the
//! answer is deny. Otherwise, if any matching statement allows, the answer is
//! allow. If nothing matches, the action is simply not granted.

use crate::model::{Effect, Policy};
use crate::wildcard::glob_match;

/// The outcome of evaluating one action against one resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    ExplicitDeny,
    NotApplicable,
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Decision::Allowed)
    }
}

/// The set of actions the analyzer reasons about. Keeping this list small and
/// explicit means blast-radius enumeration is bounded and predictable rather
/// than an open-ended search over every possible AWS action.
pub const ACTION_VOCABULARY: [&str; 6] = [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "secretsmanager:GetSecretValue",
    "lambda:InvokeFunction",
    "sts:AssumeRole",
];

fn statement_matches(
    actions: &[String],
    resources: &[String],
    action: &str,
    resource: &str,
) -> bool {
    let action_ok = actions.iter().any(|a| glob_match(a, action));
    let resource_ok = resources.iter().any(|r| glob_match(r, resource));
    action_ok && resource_ok
}

/// Evaluate one `(action, resource)` pair against a set of resolved policies.
pub fn evaluate(policies: &[&Policy], action: &str, resource: &str) -> Decision {
    let mut allowed = false;
    let mut denied = false;

    for policy in policies {
        for stmt in &policy.statements {
            if statement_matches(&stmt.actions, &stmt.resources, action, resource) {
                match stmt.effect {
                    Effect::Deny => denied = true,
                    Effect::Allow => allowed = true,
                }
            }
        }
    }

    if denied {
        Decision::ExplicitDeny
    } else if allowed {
        Decision::Allowed
    } else {
        Decision::NotApplicable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Statement;

    fn policy(name: &str, statements: Vec<Statement>) -> Policy {
        Policy {
            name: name.to_string(),
            statements,
        }
    }

    fn stmt(effect: Effect, actions: &[&str], resources: &[&str]) -> Statement {
        Statement {
            effect,
            actions: actions.iter().map(|s| s.to_string()).collect(),
            resources: resources.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn direct_allow() {
        let p = policy(
            "P",
            vec![stmt(
                Effect::Allow,
                &["s3:GetObject"],
                &["arn:aws:s3:::dev/*"],
            )],
        );
        assert_eq!(
            evaluate(&[&p], "s3:GetObject", "arn:aws:s3:::dev/file"),
            Decision::Allowed
        );
    }

    #[test]
    fn not_applicable_when_nothing_matches() {
        let p = policy(
            "P",
            vec![stmt(
                Effect::Allow,
                &["s3:GetObject"],
                &["arn:aws:s3:::dev/*"],
            )],
        );
        assert_eq!(
            evaluate(&[&p], "s3:PutObject", "arn:aws:s3:::dev/file"),
            Decision::NotApplicable
        );
    }

    #[test]
    fn explicit_deny_overrides_allow() {
        let p = policy(
            "P",
            vec![
                stmt(Effect::Allow, &["s3:*"], &["arn:aws:s3:::prod/*"]),
                stmt(Effect::Deny, &["s3:DeleteObject"], &["arn:aws:s3:::prod/*"]),
            ],
        );
        assert_eq!(
            evaluate(&[&p], "s3:PutObject", "arn:aws:s3:::prod/x"),
            Decision::Allowed
        );
        assert_eq!(
            evaluate(&[&p], "s3:DeleteObject", "arn:aws:s3:::prod/x"),
            Decision::ExplicitDeny
        );
    }

    #[test]
    fn wildcard_action_matches_vocabulary() {
        let p = policy("P", vec![stmt(Effect::Allow, &["s3:*"], &["*"])]);
        for action in ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"] {
            assert_eq!(
                evaluate(&[&p], action, "arn:aws:s3:::anything"),
                Decision::Allowed
            );
        }
    }

    #[test]
    fn deny_across_policies_still_wins() {
        let allow = policy("A", vec![stmt(Effect::Allow, &["*"], &["*"])]);
        let deny = policy(
            "D",
            vec![stmt(
                Effect::Deny,
                &["secretsmanager:GetSecretValue"],
                &["*"],
            )],
        );
        assert_eq!(
            evaluate(
                &[&allow, &deny],
                "secretsmanager:GetSecretValue",
                "arn:aws:secretsmanager:::prod/db"
            ),
            Decision::ExplicitDeny
        );
    }
}

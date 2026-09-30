//! Blast-radius traversal tests against the shipped fixtures.

use secretscope_graph::{analyze, analyze_with_tree, render_path};
use secretscope_iam::load_account;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("fixtures/aws");
    p.push(name);
    p
}

#[test]
fn direct_access_no_role_hop() {
    let acct = load_account(&fixture("direct-access")).unwrap();
    let radius = analyze(&acct, "service-user").unwrap();
    assert_eq!(radius.reachable_count, 1);
    assert_eq!(radius.privilege_paths, 0);
    let r = &radius.resources[0];
    assert!(!r.via_assumed_role);
    assert!(r.actions.contains(&"s3:PutObject".to_string()));
}

#[test]
fn assume_role_reaches_production() {
    let acct = load_account(&fixture("assume-role")).unwrap();
    let radius = analyze(&acct, "developer-user").unwrap();
    assert_eq!(radius.assumed_roles, vec!["payments-production-role"]);
    assert_eq!(radius.reachable_count, 1);
    let r = &radius.resources[0];
    assert!(r.via_assumed_role);
    assert_eq!(r.arn, "arn:aws:s3:::payments-prod/*");
    // The path should route through the policy, the assume action, and the role.
    let rendered = render_path(&r.path);
    assert!(rendered.contains("developer-user"));
    assert!(rendered.contains("sts:AssumeRole"));
    assert!(rendered.contains("payments-production-role"));
    assert!(rendered.ends_with("arn:aws:s3:::payments-prod/*"));
}

#[test]
fn demo_account_has_multiple_reachable_resources() {
    let acct = load_account(&fixture("demo-account")).unwrap();
    let radius = analyze(&acct, "developer-user").unwrap();
    // dev-data (direct), payments-prod (via role), prod/database secret (via role)
    assert_eq!(radius.reachable_count, 3);
    let arns: Vec<&str> = radius.resources.iter().map(|r| r.arn.as_str()).collect();
    assert!(arns.contains(&"arn:aws:s3:::dev-data/*"));
    assert!(arns.contains(&"arn:aws:s3:::payments-prod/*"));
    assert!(arns
        .iter()
        .any(|a| a.contains("secretsmanager") && a.contains("prod/database")));
}

#[test]
fn cyclic_roles_terminate_and_reach_deep_resource() {
    let acct = load_account(&fixture("cyclic-roles")).unwrap();
    // If cycle handling were wrong this call would not return.
    let (radius, tree) = analyze_with_tree(&acct, "entry-user").unwrap();
    assert_eq!(radius.reachable_count, 1);
    assert_eq!(radius.resources[0].arn, "arn:aws:s3:::deep-bucket/*");
    // role-a, role-b, role-c all assumed.
    assert_eq!(radius.assumed_roles.len(), 3);
    // The tree should mark the back edge as a cycle rather than loop forever.
    assert!(tree.contains("(cycle)"));
}

#[test]
fn safe_account_reaches_only_dev_data() {
    let acct = load_account(&fixture("safe-account")).unwrap();
    let radius = analyze(&acct, "analyst-user").unwrap();
    assert_eq!(radius.reachable_count, 1);
    assert!(!radius.resources[0].via_assumed_role);
    assert!(!radius.resources[0].sensitive);
}

#[test]
fn explicit_deny_removes_delete_capability() {
    let acct = load_account(&fixture("explicit-deny")).unwrap();
    let radius = analyze(&acct, "ops-user").unwrap();
    let actions = &radius.resources[0].actions;
    assert!(actions.contains(&"s3:GetObject".to_string()));
    assert!(actions.contains(&"s3:PutObject".to_string()));
    assert!(!actions.contains(&"s3:DeleteObject".to_string()));
}

#[test]
fn unknown_principal_returns_none() {
    let acct = load_account(&fixture("demo-account")).unwrap();
    assert!(analyze(&acct, "nobody").is_none());
}

#[test]
fn path_reconstruction_is_deterministic() {
    let acct = load_account(&fixture("demo-account")).unwrap();
    let a = analyze(&acct, "developer-user").unwrap();
    let b = analyze(&acct, "developer-user").unwrap();
    assert_eq!(a, b);
}

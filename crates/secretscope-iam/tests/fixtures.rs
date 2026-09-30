//! Integration tests that load the real fixtures shipped with the project.

use secretscope_iam::{evaluate, load_account, Decision, PrincipalRef};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    // tests run from the crate dir; walk up to the workspace root.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("fixtures/aws");
    p.push(name);
    p
}

#[test]
fn demo_account_loads_and_maps_credential() {
    let acct = load_account(&fixture("demo-account")).unwrap();
    assert_eq!(acct.users.len(), 1);
    assert_eq!(acct.roles.len(), 1);

    let fp = "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3";
    assert_eq!(acct.principal_for_fingerprint(fp), Some("developer-user"));

    let dev = acct.principal_by_name("developer-user").unwrap();
    assert!(matches!(dev, PrincipalRef::User(_)));
    let policies = acct.resolve_policies(dev.policy_names());
    assert_eq!(policies.len(), 1);

    // developer-user can assume the production role.
    assert_eq!(
        evaluate(
            &policies,
            "sts:AssumeRole",
            "arn:aws:iam::123456789012:role/payments-production-role"
        ),
        Decision::Allowed
    );
}

#[test]
fn explicit_deny_fixture_blocks_delete() {
    let acct = load_account(&fixture("explicit-deny")).unwrap();
    let ops = acct.principal_by_name("ops-user").unwrap();
    let policies = acct.resolve_policies(ops.policy_names());

    assert_eq!(
        evaluate(&policies, "s3:PutObject", "arn:aws:s3:::payments-prod/x"),
        Decision::Allowed
    );
    assert_eq!(
        evaluate(&policies, "s3:DeleteObject", "arn:aws:s3:::payments-prod/x"),
        Decision::ExplicitDeny
    );
}

#[test]
fn role_lookup_by_resource_arn() {
    let acct = load_account(&fixture("demo-account")).unwrap();
    let role = acct
        .role_for_resource("arn:aws:iam::123456789012:role/payments-production-role")
        .unwrap();
    assert_eq!(role.name, "payments-production-role");
}

#[test]
fn missing_policy_resolves_to_nothing() {
    let acct = load_account(&fixture("safe-account")).unwrap();
    // A name that does not exist just yields no policy, no panic.
    let resolved = acct.resolve_policies(&["DoesNotExist".to_string()]);
    assert!(resolved.is_empty());
}

#[test]
fn invalid_fixture_is_an_error() {
    let dir = std::env::temp_dir().join(format!(
        "secretscope-badiam-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("users.json"), "{ this is not valid json ").unwrap();

    assert!(load_account(&dir).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

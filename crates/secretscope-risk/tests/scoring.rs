//! Risk scoring tests, including the conceptual scenarios from the design.

use secretscope_graph::analyze;
use secretscope_iam::load_account;
use secretscope_risk::{assess, Severity};
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
fn unmapped_credential_is_low() {
    let r = assess(false, None);
    assert_eq!(r.severity, Severity::Low);
    assert!(r.reasons.iter().any(|s| s.contains("detected")));
    assert!(r.reasons.iter().any(|s| s.contains("no IAM identity")));
}

#[test]
fn read_only_dev_access_is_moderate() {
    let acct = load_account(&fixture("safe-account")).unwrap();
    let blast = analyze(&acct, "analyst-user").unwrap();
    let r = assess(true, Some(&blast));
    assert_eq!(r.severity, Severity::Medium);
}

#[test]
fn writing_production_is_high_or_critical() {
    let acct = load_account(&fixture("assume-role")).unwrap();
    let blast = analyze(&acct, "developer-user").unwrap();
    let r = assess(true, Some(&blast));
    // assume(3) + production(3) + write(2) + mapped(1) + detected(1) = 10 -> critical,
    // certainly at least HIGH.
    assert!(r.severity.meets(Severity::High));
    assert!(r.reasons.iter().any(|s| s.contains("privilege path")));
}

#[test]
fn assume_and_secrets_is_critical() {
    let acct = load_account(&fixture("demo-account")).unwrap();
    let blast = analyze(&acct, "developer-user").unwrap();
    let r = assess(true, Some(&blast));
    assert_eq!(r.severity, Severity::Critical);
    assert!(r.reasons.iter().any(|s| s.contains("secret value")));
    assert!(r.reasons.iter().any(|s| s.contains("privilege path")));
}

#[test]
fn scoring_is_deterministic() {
    let acct = load_account(&fixture("demo-account")).unwrap();
    let blast = analyze(&acct, "developer-user").unwrap();
    assert_eq!(assess(true, Some(&blast)), assess(true, Some(&blast)));
}

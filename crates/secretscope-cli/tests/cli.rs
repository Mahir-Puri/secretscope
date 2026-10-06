//! End-to-end CLI tests driving the compiled binary.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_secretscope")
}

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn fixture(rel: &str) -> PathBuf {
    workspace_root().join(rel)
}

#[test]
fn vulnerable_repo_with_iam_is_critical_json() {
    let out = Command::new(bin())
        .args(["scan"])
        .arg(fixture("fixtures/repositories/vulnerable"))
        .arg("--iam-dir")
        .arg(fixture("fixtures/aws/demo-account"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();

    // The raw key must never appear anywhere in output.
    assert!(
        !stdout.contains("AKIAIOSFODNN7EXAMPLE"),
        "raw secret leaked"
    );

    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["scan"]["findings"], 1);
    assert_eq!(v["scan"]["max_severity"], "critical");
    let f = &v["findings"][0];
    assert_eq!(f["credential_type"], "aws_access_key_id");
    assert_eq!(f["principal"], "developer-user");
    assert_eq!(f["severity"], "critical");
    assert_eq!(f["fingerprint"], "1a5d44a2dca1");
    assert_eq!(f["privilege_paths"], 1);
}

#[test]
fn fail_on_high_exits_one_when_critical() {
    let status = Command::new(bin())
        .args(["scan"])
        .arg(fixture("fixtures/repositories/vulnerable"))
        .arg("--iam-dir")
        .arg(fixture("fixtures/aws/demo-account"))
        .args(["--fail-on", "high", "--format", "json"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}

#[test]
fn unmapped_key_without_iam_is_low_and_passes_gate() {
    // No --iam-dir, so the key cannot be mapped: severity should be low and a
    // high gate should pass with exit 0.
    let status = Command::new(bin())
        .args(["scan"])
        .arg(fixture("fixtures/repositories/vulnerable"))
        .args(["--fail-on", "high", "--format", "json"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
}

#[test]
fn clean_repo_reports_nothing() {
    let out = Command::new(bin())
        .args(["scan"])
        .arg(fixture("fixtures/repositories/clean"))
        .args(["--fail-on", "low", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.stdout).unwrap()).unwrap();
    assert_eq!(v["scan"]["findings"], 0);
}

#[test]
fn missing_iam_dir_is_usage_error() {
    let status = Command::new(bin())
        .args(["scan"])
        .arg(fixture("fixtures/repositories/vulnerable"))
        .arg("--iam-dir")
        .arg(fixture("fixtures/aws/does-not-exist"))
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}

//! Integration tests for git history scanning.
//!
//! These build small throwaway repositories with the git binary. If git is not
//! present the tests are skipped rather than failed.

use secretscope_scanner::{scan, scan_history, DetectorConfig, Origin, ScanOptions};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .expect("git should run");
    assert!(status.success(), "git {:?} failed", args);
}

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

fn repo(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("secretscope-git-{tag}-{nanos}"));
    fs::create_dir_all(&p).unwrap();
    git(&p, &["init", "-q"]);
    git(&p, &["config", "user.email", "test@example.com"]);
    git(&p, &["config", "user.name", "Test"]);
    p
}

#[test]
fn finds_secret_that_was_later_deleted() {
    if !git_available() {
        return;
    }
    let dir = repo("deleted");
    // Commit 1: introduce a secret.
    fs::write(
        dir.join("app.env"),
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-q", "-m", "add config"]);
    // Commit 2: remove the secret from the working tree.
    fs::write(dir.join("app.env"), "AWS_ACCESS_KEY_ID=\n").unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-q", "-m", "scrub config"]);

    // Working tree alone: nothing.
    let clean = scan(&ScanOptions::new(&dir)).unwrap();
    assert!(clean.is_empty(), "working tree should be clean");

    // History: the secret is still there in commit 1.
    let hist = scan_history(&dir, &[], &DetectorConfig::default()).unwrap();
    assert_eq!(hist.len(), 1);
    assert!(matches!(hist[0].origin, Origin::GitHistory { .. }));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn clean_history_reports_nothing() {
    if !git_available() {
        return;
    }
    let dir = repo("clean");
    fs::write(dir.join("README.md"), "# hello\nno secrets here\n").unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-q", "-m", "init"]);

    let hist = scan_history(&dir, &[], &DetectorConfig::default()).unwrap();
    assert!(hist.is_empty());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn history_on_non_git_dir_errors() {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "secretscope-nogit-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();

    let err = scan_history(&dir, &[], &DetectorConfig::default());
    assert!(err.is_err(), "scanning history of a non-repo should error");
    fs::remove_dir_all(&dir).ok();
}

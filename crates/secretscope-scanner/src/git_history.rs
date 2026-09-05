//! Git history scanning.
//!
//! Rather than pull in a native libgit2 binding, this talks to the installed
//! `git` binary through short, read-only commands. That keeps the dependency
//! surface small and means the scan can never rewrite or check out anything.
//!
//! The approach is deliberately simple. For every commit reachable from any
//! ref, we look at the files that commit changed and read each file's contents
//! as they were at that commit. A secret that was added and later deleted is
//! still found, attributed to the commit that introduced it. This is not an
//! incremental index; it re-reads changed blobs, which is fine for the sizes
//! this project targets.

use crate::detectors::DetectorConfig;
use crate::finding::{Finding, Origin};
use crate::walk::{is_excluded, is_probably_binary, scan_text};
use std::path::Path;
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("`{0}` is not a git repository, so history cannot be scanned")]
    NotARepository(String),
    #[error("failed to run git: {0}")]
    GitUnavailable(String),
    #[error("git command failed: {0}")]
    GitCommand(String),
}

fn run_git(root: &Path, args: &[&str]) -> Result<Vec<u8>, GitError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|e| GitError::GitUnavailable(e.to_string()))?;
    if !output.status.success() {
        return Err(GitError::GitCommand(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(output.stdout)
}

/// Whether `root` is inside a git work tree.
pub fn is_git_repo(root: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Scan every commit reachable from any ref for secrets.
pub fn scan_history(
    root: &Path,
    excludes: &[String],
    cfg: &DetectorConfig,
) -> Result<Vec<Finding>, GitError> {
    if !is_git_repo(root) {
        return Err(GitError::NotARepository(root.display().to_string()));
    }

    let commits_raw = run_git(root, &["rev-list", "--all"])?;
    let commits = String::from_utf8_lossy(&commits_raw);

    let mut findings = Vec::new();
    for commit in commits.lines() {
        let commit = commit.trim();
        if commit.is_empty() {
            continue;
        }
        // Files touched by this commit. --root lets the initial commit list its
        // files instead of showing nothing.
        let names_raw = run_git(
            root,
            &[
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                "--root",
                commit,
            ],
        )?;
        let names = String::from_utf8_lossy(&names_raw);
        for path in names.lines() {
            let path = path.trim();
            if path.is_empty() || is_excluded(Path::new(path), excludes) {
                continue;
            }
            // Contents of the file as of this commit. Fails for paths deleted in
            // this commit, which we simply skip.
            let spec = format!("{commit}:{path}");
            let blob = match run_git(root, &["show", &spec]) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if is_probably_binary(&blob) {
                continue;
            }
            let text = String::from_utf8_lossy(&blob);
            let origin = Origin::GitHistory {
                commit: commit.to_string(),
            };
            findings.extend(scan_text(&text, path, cfg, origin));
        }
    }

    dedup(&mut findings);
    Ok(findings)
}

/// Remove exact duplicates (same fingerprint, path, line, and origin).
fn dedup(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let key = (
            f.fingerprint.clone(),
            f.path.clone(),
            f.line,
            format!("{:?}", f.origin),
        );
        seen.insert(key)
    });
}

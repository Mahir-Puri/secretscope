//! Filesystem traversal and per-file scanning.
//!
//! Traversal skips excluded directories, the `.git` directory, files that look
//! binary, and files above a size limit. Reading `.git` internals directly is
//! avoided on purpose; history scanning goes through the git binary instead
//! (see `git_history`).

use crate::detectors::{detect_line, DetectorConfig};
use crate::finding::{Finding, Origin};
use crate::secret_to_finding;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Default directory names that are never scanned.
pub const DEFAULT_EXCLUDES: [&str; 3] = [".git", "target", "node_modules"];

/// Files larger than this are skipped. Real source rarely exceeds this and
/// scanning large blobs line by line is slow and noisy.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Returns true when `rel` should be skipped given the configured excludes.
pub fn is_excluded(rel: &Path, excludes: &[String]) -> bool {
    // Skip if any path component matches a default excluded directory name.
    for comp in rel.components() {
        let name = comp.as_os_str().to_string_lossy();
        if DEFAULT_EXCLUDES.contains(&name.as_ref()) {
            return true;
        }
    }
    // Skip if the relative path contains any user-supplied exclude substring.
    let rel_str = rel.to_string_lossy();
    excludes
        .iter()
        .any(|e| !e.is_empty() && rel_str.contains(e.as_str()))
}

/// Heuristic binary check: a NUL byte in the first chunk means binary.
pub fn is_probably_binary(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(8000)];
    window.contains(&0)
}

/// Collect the files that should be scanned under `root`.
pub fn collect_files(root: &Path, excludes: &[String], max_bytes: u64) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(path);
        if is_excluded(rel, excludes) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if meta.len() > max_bytes {
                continue;
            }
        }
        files.push(path.to_path_buf());
    }
    files.sort();
    files
}

/// Scan one file from the working tree.
pub fn scan_file(path: &Path, root: &Path, cfg: &DetectorConfig) -> Vec<Finding> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    if is_probably_binary(&bytes) {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();
    scan_text(&text, &rel, cfg, Origin::WorkingTree)
}

/// Scan an in-memory blob of text, tagging each finding with `origin`.
pub fn scan_text(text: &str, rel_path: &str, cfg: &DetectorConfig, origin: Origin) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        for m in detect_line(line, cfg) {
            findings.push(secret_to_finding(m, rel_path, idx + 1, origin.clone()));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_git_and_target() {
        assert!(is_excluded(Path::new(".git/config"), &[]));
        assert!(is_excluded(Path::new("target/debug/thing"), &[]));
        assert!(!is_excluded(Path::new("src/main.rs"), &[]));
    }

    #[test]
    fn honours_custom_exclude() {
        let ex = vec!["fixtures/known-safe".to_string()];
        assert!(is_excluded(Path::new("fixtures/known-safe/a.txt"), &ex));
        assert!(!is_excluded(Path::new("fixtures/other/a.txt"), &ex));
    }

    #[test]
    fn detects_binary_by_nul() {
        assert!(is_probably_binary(b"abc\0def"));
        assert!(!is_probably_binary(b"plain text"));
    }
}

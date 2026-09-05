//! SecretScope scanner.
//!
//! This crate finds credentials in a repository's working tree and, on request,
//! in its git history. It is built around one safety rule: a raw secret is used
//! only long enough to compute a redacted form and a fingerprint, then it is
//! zeroized and dropped. Nothing that leaves this crate carries the original
//! value.

mod detectors;
mod entropy;
mod finding;
mod fingerprint;
mod git_history;
mod redact;
mod walk;

pub use detectors::{detect_line, DetectorConfig, RawMatch};
pub use entropy::shannon;
pub use finding::{CredentialKind, Finding, Origin};
pub use fingerprint::{fingerprint, prefix};
pub use git_history::{is_git_repo, scan_history, GitError};
pub use walk::{
    collect_files, is_excluded, is_probably_binary, scan_file, scan_text, DEFAULT_EXCLUDES,
    DEFAULT_MAX_FILE_BYTES,
};

use rayon::prelude::*;
use std::path::PathBuf;
use zeroize::Zeroize;

/// Options controlling a scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub root: PathBuf,
    pub excludes: Vec<String>,
    pub detector: DetectorConfig,
    pub scan_history: bool,
    pub max_file_bytes: u64,
    /// When true, scan files in parallel with rayon. Exposed so the benchmark
    /// can compare sequential and parallel scanning on the same input.
    pub parallel: bool,
}

impl ScanOptions {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        ScanOptions {
            root: root.into(),
            excludes: Vec::new(),
            detector: DetectorConfig::default(),
            scan_history: false,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            parallel: true,
        }
    }
}

/// Errors that can stop a scan. A missing IAM mapping is not one of them; that
/// is handled downstream and never fails the scan.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error(transparent)]
    Git(#[from] GitError),
}

/// Convert a raw detector match into a [`Finding`], redacting and fingerprinting
/// the secret and then wiping the raw copy from memory.
pub(crate) fn secret_to_finding(
    mut m: RawMatch,
    path: &str,
    line: usize,
    origin: Origin,
) -> Finding {
    let full = fingerprint(&m.secret);
    let short = prefix(&full);
    let redacted = match m.kind {
        // A PEM header carries no secret material, but we still avoid printing
        // the surrounding key body, so we show a fixed marker.
        CredentialKind::PrivateKey => "PEM private key block".to_string(),
        _ => redact::redact(&m.secret),
    };
    // Wipe the raw secret. Everything we keep is derived and non-reversible.
    m.secret.zeroize();

    Finding {
        kind: m.kind,
        path: path.to_string(),
        line,
        redacted,
        fingerprint_prefix: short,
        fingerprint: full,
        origin,
    }
}

/// Run a scan and return every finding.
pub fn scan(opts: &ScanOptions) -> Result<Vec<Finding>, ScanError> {
    let files = collect_files(&opts.root, &opts.excludes, opts.max_file_bytes);

    let mut findings: Vec<Finding> = if opts.parallel {
        files
            .par_iter()
            .flat_map(|p| scan_file(p, &opts.root, &opts.detector))
            .collect()
    } else {
        files
            .iter()
            .flat_map(|p| scan_file(p, &opts.root, &opts.detector))
            .collect()
    };

    if opts.scan_history {
        let history = scan_history(&opts.root, &opts.excludes, &opts.detector)?;
        findings.extend(history);
    }

    findings.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.line.cmp(&b.line))
            .then(a.fingerprint_prefix.cmp(&b.fingerprint_prefix))
    });
    Ok(findings)
}

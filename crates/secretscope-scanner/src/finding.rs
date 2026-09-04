//! Types that describe a detected credential.
//!
//! A [`Finding`] is the only thing that leaves the scanner, and it is
//! deliberately built so that the raw secret can never travel with it. The
//! full fingerprint is kept in memory for IAM correlation but is marked
//! `#[serde(skip)]`, so it never reaches JSON output or logs.

use serde::{Deserialize, Serialize};

/// The category of credential a detector matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    AwsAccessKeyId,
    GitHubToken,
    PrivateKey,
    GenericHighEntropy,
}

impl CredentialKind {
    /// Human friendly label used in the CLI.
    pub fn label(self) -> &'static str {
        match self {
            CredentialKind::AwsAccessKeyId => "AWS Access Key",
            CredentialKind::GitHubToken => "GitHub Token",
            CredentialKind::PrivateKey => "Private Key",
            CredentialKind::GenericHighEntropy => "High-entropy Secret",
        }
    }

    /// Whether this credential kind can be mapped to an AWS identity.
    pub fn is_aws(self) -> bool {
        matches!(self, CredentialKind::AwsAccessKeyId)
    }
}

/// Where a finding came from: the current working tree or a past commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Origin {
    WorkingTree,
    GitHistory { commit: String },
}

/// A single detected credential.
///
/// `fingerprint` holds the full SHA-256 hex digest and is used only for
/// matching against synthetic IAM metadata. It is never serialized. Callers
/// that want to show something to a human use `fingerprint_prefix`, which is a
/// short, non-reversible label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: CredentialKind,
    pub path: String,
    pub line: usize,
    /// Redacted representation, e.g. `AKIA************7J2K`.
    pub redacted: String,
    /// Short, user-facing fingerprint prefix, e.g. `5e26c4`.
    pub fingerprint_prefix: String,
    /// Full SHA-256 hex digest, kept for IAM correlation only. Never serialized.
    #[serde(skip)]
    pub fingerprint: String,
    pub origin: Origin,
}

impl Finding {
    pub fn location(&self) -> String {
        format!("{}:{}", self.path, self.line)
    }
}

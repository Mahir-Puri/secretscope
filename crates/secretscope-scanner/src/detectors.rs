//! Line-level credential detectors.
//!
//! Each detector reports the raw matched text. The raw text is turned into a
//! redacted string and a fingerprint by the scanner and is then dropped. No
//! detector here ever writes the raw value anywhere durable.
//!
//! The generic detector deliberately combines two signals: a sensitive looking
//! variable name and a high-entropy value. Requiring both keeps false
//! positives low, which matters because a scanner that cries wolf gets ignored.

use crate::entropy::shannon;
use crate::finding::CredentialKind;
use once_cell::sync::Lazy;
use regex::Regex;

/// Tunable inputs for detection.
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    pub entropy_threshold: f64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        DetectorConfig {
            entropy_threshold: 4.2,
        }
    }
}

/// A raw detector hit. `secret` is the sensitive material and must be redacted
/// and fingerprinted before it leaves the scanner.
#[derive(Debug, Clone)]
pub struct RawMatch {
    pub kind: CredentialKind,
    pub secret: String,
}

static AWS_KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b").unwrap());

static GITHUB_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[0-9a-zA-Z_]{40,})\b").unwrap()
});

static PRIVATE_KEY_HEADER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----").unwrap()
});

// Captures `name` and `value` from simple assignments: NAME=value, NAME: value,
// NAME = "value". The value stops at quotes, whitespace, or a comment marker.
static ASSIGNMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=]\s*["']?([^"'\s#]{6,})["']?"#).unwrap()
});

// A name is "sensitive" if it looks like it holds a credential.
static SENSITIVE_NAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|auth|credential|private[_-]?key)")
        .unwrap()
});

/// Characters that commonly appear in real credentials (base64, hex, tokens).
/// Anything outside this set is treated as a sign the value is code, not a
/// secret.
fn is_secret_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '.' | '-')
}

fn is_placeholder(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    const NEEDLES: [&str; 10] = [
        "example",
        "changeme",
        "your-",
        "your_",
        "placeholder",
        "redacted",
        "xxxx",
        "dummy",
        "sample",
        "todo",
    ];
    if NEEDLES.iter().any(|n| v.contains(n)) {
        return true;
    }
    // Template references such as ${VAR}, {{ var }}, <value>, $VAR
    value.starts_with('$')
        || value.starts_with("${")
        || value.starts_with("{{")
        || value.starts_with('<')
}

/// Run every detector against a single line of text.
pub fn detect_line(line: &str, cfg: &DetectorConfig) -> Vec<RawMatch> {
    let mut out = Vec::new();

    for cap in AWS_KEY.captures_iter(line) {
        out.push(RawMatch {
            kind: CredentialKind::AwsAccessKeyId,
            secret: cap[1].to_string(),
        });
    }

    for cap in GITHUB_TOKEN.captures_iter(line) {
        out.push(RawMatch {
            kind: CredentialKind::GitHubToken,
            secret: cap[1].to_string(),
        });
    }

    if let Some(m) = PRIVATE_KEY_HEADER.find(line) {
        out.push(RawMatch {
            kind: CredentialKind::PrivateKey,
            secret: m.as_str().to_string(),
        });
    }

    // Generic high-entropy assignment. Only fire when the name is sensitive and
    // the value is both long enough and high entropy, and is not already an AWS
    // or GitHub match on this line.
    for cap in ASSIGNMENT.captures_iter(line) {
        let name = &cap[1];
        let value = &cap[2];
        if !SENSITIVE_NAME.is_match(name) {
            continue;
        }
        if value.len() < 12 || is_placeholder(value) {
            continue;
        }
        // Real credentials are opaque token-like strings. Values that contain
        // characters typical of code (brackets, colons in paths, backticks)
        // are almost always source, not secrets, so skip them. This keeps the
        // generic detector from flagging things like `token = build_token(x)`.
        if !value.chars().all(is_secret_char) {
            continue;
        }
        if shannon(value) < cfg.entropy_threshold {
            continue;
        }
        let already = out.iter().any(|m| m.secret == value);
        if already {
            continue;
        }
        out.push(RawMatch {
            kind: CredentialKind::GenericHighEntropy,
            secret: value.to_string(),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(line: &str) -> Vec<CredentialKind> {
        detect_line(line, &DetectorConfig::default())
            .into_iter()
            .map(|m| m.kind)
            .collect()
    }

    #[test]
    fn detects_aws_access_key() {
        assert_eq!(
            kinds(&format!("aws_key = {}{}", "AKIA", "IOSFODNN7EXAMPLE")),
            vec![CredentialKind::AwsAccessKeyId]
        );
    }

    #[test]
    fn detects_github_classic_token() {
        let line = format!(
            "token: {}{}",
            "ghp_", "1234567890abcdefghijklmnopqrstuvwx12"
        );
        assert!(kinds(&line).contains(&CredentialKind::GitHubToken));
    }

    #[test]
    fn detects_private_key_header() {
        let line = format!("{}RSA PRIVATE KEY-----", "-----BEGIN ");
        assert_eq!(kinds(&line), vec![CredentialKind::PrivateKey]);
    }

    #[test]
    fn detects_generic_high_entropy_secret() {
        let secret = format!("{}{}", "aB3xZ9qL7wR", "2tP5mN8kQ1vC4");
        let line = format!(r#"API_KEY = "{secret}""#);
        assert!(kinds(&line).contains(&CredentialKind::GenericHighEntropy));
    }

    #[test]
    fn ignores_low_entropy_password() {
        assert!(kinds("password = hunter2").is_empty());
    }

    #[test]
    fn ignores_git_hash_in_nonsensitive_name() {
        let line = r#"commit = "3f2a1b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a""#;
        assert!(kinds(line).is_empty());
    }

    #[test]
    fn ignores_placeholder_value() {
        assert!(kinds(r#"API_KEY = "your-api-key-here""#).is_empty());
        assert!(kinds("SECRET = ${VAULT_SECRET}").is_empty());
    }

    #[test]
    fn ignores_code_like_value_in_sensitive_name() {
        // A sensitive variable name assigned a code expression is not a secret.
        assert!(kinds("credential_type = serde_json::to_value(kind)").is_empty());
        assert!(kinds("let token = build_token(request);").is_empty());
    }

    #[test]
    fn ignores_env_reference() {
        assert!(kinds("AWS_SECRET_ACCESS_KEY=$AWS_SECRET").is_empty());
    }
}

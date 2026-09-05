//! Deterministic fingerprints for detected secrets.
//!
//! A fingerprint is `SHA-256(secret)` rendered as hex. We use it for two
//! things: correlating a detected credential with synthetic IAM metadata
//! without ever storing the credential, and de-duplicating the same secret
//! seen in several places. Hashing does not make a leaked credential safe. If
//! a real key leaks it must still be rotated. The fingerprint only lets us
//! talk about "the same secret" without holding onto it.

use sha2::{Digest, Sha256};

/// Full SHA-256 hex digest of `secret`.
pub fn fingerprint(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    hex(&digest)
}

/// A short, user-facing prefix of a full fingerprint (first 12 hex chars).
pub fn prefix(full: &str) -> String {
    full.chars().take(12).collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_deterministic() {
        assert_eq!(fingerprint("hello"), fingerprint("hello"));
    }

    #[test]
    fn differs_for_different_input() {
        assert_ne!(fingerprint("hello"), fingerprint("world"));
    }

    #[test]
    fn matches_known_sha256() {
        // sha256("") is well known.
        assert_eq!(
            fingerprint(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn prefix_is_twelve_chars() {
        let f = fingerprint("something");
        assert_eq!(prefix(&f).len(), 12);
    }
}

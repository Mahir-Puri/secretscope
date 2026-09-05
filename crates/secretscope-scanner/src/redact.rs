//! Turning a raw secret into something safe to print.
//!
//! The rule is simple: keep at most the first four and last four characters,
//! mask the middle, and fully mask anything short enough that the ends would
//! give the value away. The number of mask characters is capped so the output
//! does not leak the exact length of a long secret.

const MAX_MASK: usize = 12;

/// Produce a redacted form of `secret`.
///
/// Examples:
/// - a 20-character AWS key becomes `AKIA************MPLE`
/// - `short` becomes `*****`
pub fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let len = chars.len();

    if len <= 8 {
        return "*".repeat(len.max(1));
    }

    let first: String = chars[..4].iter().collect();
    let last: String = chars[len - 4..].iter().collect();
    let mask = (len - 8).min(MAX_MASK);
    format!("{first}{}{last}", "*".repeat(mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_middle_of_long_secret() {
        let key = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
        let r = redact(&key);
        assert!(r.starts_with("AKIA"));
        assert!(r.ends_with("MPLE"));
        assert!(r.contains('*'));
        assert!(!r.contains("IOSFODNN"));
    }

    #[test]
    fn fully_masks_short_secret() {
        assert_eq!(redact("short"), "*****");
        assert_eq!(redact("abcdefgh"), "********");
    }

    #[test]
    fn mask_length_is_capped() {
        let long = "A".repeat(200);
        let r = redact(&long);
        // 4 + capped mask + 4
        assert_eq!(r.len(), 4 + super::MAX_MASK + 4);
    }
}

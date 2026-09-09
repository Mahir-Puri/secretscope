//! Glob matching for IAM actions and resource ARNs.
//!
//! AWS uses `*` as a wildcard in both action names (`s3:*`) and resource ARNs
//! (`arn:aws:s3:::bucket/*`). This module implements the only wildcard we
//! support, `*`, which matches any run of characters including an empty run.
//! There is no `?` and there are no character classes, which keeps the matcher
//! small and easy to reason about.

/// Return true when `pattern` matches `text`, treating `*` in the pattern as
/// "any sequence of characters".
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    // Two-pointer scan with backtracking to the last `*`.
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            // Backtrack: let the last `*` swallow one more character.
            pi = s + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    // Any trailing pattern characters must all be `*`.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(glob_match("s3:GetObject", "s3:GetObject"));
        assert!(!glob_match("s3:GetObject", "s3:PutObject"));
    }

    #[test]
    fn service_wildcard() {
        assert!(glob_match("s3:*", "s3:GetObject"));
        assert!(glob_match("s3:*", "s3:DeleteObject"));
        assert!(!glob_match("s3:*", "lambda:InvokeFunction"));
    }

    #[test]
    fn full_wildcard() {
        assert!(glob_match("*", "anything:at:all"));
    }

    #[test]
    fn resource_prefix() {
        assert!(glob_match(
            "arn:aws:s3:::payments-prod/*",
            "arn:aws:s3:::payments-prod/ledger.csv"
        ));
        assert!(!glob_match(
            "arn:aws:s3:::payments-prod/*",
            "arn:aws:s3:::dev-data/notes.txt"
        ));
    }

    #[test]
    fn star_matches_empty() {
        assert!(glob_match("prefix*", "prefix"));
    }
}

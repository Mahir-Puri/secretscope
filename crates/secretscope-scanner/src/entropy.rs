//! Shannon entropy over the characters of a string.
//!
//! This is one signal among several. A high value means the characters are
//! spread out and hard to predict, which is typical of random keys and tokens.
//! It is not proof of a secret on its own, which is why the generic detector
//! also looks at the surrounding variable name.

use std::collections::HashMap;

/// Shannon entropy in bits per character. Returns 0.0 for the empty string.
pub fn shannon(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in input.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = input.chars().count() as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon(""), 0.0);
    }

    #[test]
    fn single_repeated_char_is_zero() {
        assert_eq!(shannon("aaaaaaaa"), 0.0);
    }

    #[test]
    fn random_looking_string_is_high() {
        assert!(shannon("aB3xZ9qL7wR2tP5m") > 3.5);
    }

    #[test]
    fn english_word_is_lower_than_random() {
        assert!(shannon("password") < shannon("g7X2qL9zR4wT1nB8"));
    }
}

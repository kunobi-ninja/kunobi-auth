//! Constant-time secret comparison.

/// Constant-time equality for secrets such as bearer tokens and per-lease
/// connect tokens.
///
/// Returns `false` immediately on a length mismatch (the length of a secret is
/// not itself sensitive), but otherwise compares **every** byte so the running
/// time does not depend on the position of the first differing byte. Prefer this
/// over `==` for any value an attacker may try to guess one byte at a time.
///
/// ```
/// use kunobi_auth::secret_eq;
/// assert!(secret_eq("s3cret", "s3cret"));
/// assert!(!secret_eq("s3cret", "s3crex"));
/// assert!(!secret_eq("s3cret", "s3cret-extra"));
/// ```
pub fn secret_eq(a: &str, b: &str) -> bool {
    secret_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Shared byte primitive for string secrets and OAuth's byte-slice API.
pub(crate) fn secret_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_secrets_preserve_non_utf8_content() {
        assert!(secret_eq_bytes(&[0xff, 0, 0x80], &[0xff, 0, 0x80]));
        assert!(!secret_eq_bytes(&[0xff, 0, 0x80], &[0xff, 0, 0x81]));
        assert!(!secret_eq_bytes(&[0xff], &[0xff, 0]));
    }

    #[test]
    fn equal_secrets_match() {
        assert!(secret_eq("secret", "secret"));
        assert!(secret_eq("", ""));
    }

    #[test]
    fn same_length_difference_rejected() {
        assert!(!secret_eq("secret", "secrex"));
    }

    #[test]
    fn length_mismatch_rejected() {
        assert!(!secret_eq("secret", "secret-extra"));
        assert!(!secret_eq("", "x"));
        assert!(!secret_eq("x", ""));
    }
}

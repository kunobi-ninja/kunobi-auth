//! RFC 7636 PKCE (S256 only) and the CSRF `state` nonce.
//!
//! S256 is the only method offered. `plain` is permitted by the RFC and by some
//! servers, but a downgrade to `plain` removes the entire protection, so it is
//! not implementable here rather than merely discouraged.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// A PKCE verifier and its S256 challenge.
///
/// The verifier is secret: it is the only thing that stops an attacker who
/// intercepts the authorization code (on a loopback redirect, any local process
/// that wins the race to the port) from redeeming it. It is zeroized on drop
/// and deliberately implements neither `Debug` nor `Clone`.
pub struct Pkce {
    verifier: String,
    challenge: String,
}

impl Pkce {
    /// Generate a fresh verifier (32 CSPRNG bytes, base64url) and its challenge.
    pub fn generate() -> anyhow::Result<Self> {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw)
            .map_err(|e| anyhow::anyhow!("failed to read OS entropy for PKCE verifier: {e}"))?;
        let verifier = URL_SAFE_NO_PAD.encode(raw);
        raw.zeroize();
        Ok(Self::from_verifier(verifier))
    }

    /// Build from an existing verifier. Test-facing; production uses
    /// [`Pkce::generate`].
    pub fn from_verifier(verifier: String) -> Self {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }

    /// The `code_verifier` sent to the token endpoint.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The `code_challenge` sent to the authorization endpoint.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Always `"S256"`. A named constant so a caller cannot accidentally
    /// advertise `plain` for a challenge that is in fact hashed.
    pub const METHOD: &'static str = "S256";
}

impl Drop for Pkce {
    fn drop(&mut self) {
        self.verifier.zeroize();
    }
}

/// A CSRF `state` value: 32 CSPRNG bytes, base64url.
///
/// Compared with [`state_matches`], never with `==` at the call site, so the
/// comparison stays constant-time as the code moves.
pub fn generate_state() -> anyhow::Result<String> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw)
        .map_err(|e| anyhow::anyhow!("failed to read OS entropy for OAuth state: {e}"))?;
    let state = URL_SAFE_NO_PAD.encode(raw);
    raw.zeroize();
    Ok(state)
}

/// Constant-time comparison of an expected `state` against the one the
/// authorization server sent back.
pub fn state_matches(expected: &str, actual: &str) -> bool {
    constant_time_eq(expected.as_bytes(), actual.as_bytes())
}

/// Length-revealing but content-constant-time byte comparison.
///
/// Both operands here are fixed-length base64url of 32 bytes, so the length
/// leak carries nothing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    crate::common::secret::secret_eq_bytes(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical RFC 7636 Appendix B vector. This is the one thing in PKCE
    /// that is easy to get wrong (hashing the base64 of the verifier instead of
    /// the verifier's ASCII bytes) and impossible to notice without a fixture:
    /// a wrong challenge only fails at the *token* endpoint, long after the
    /// user has consented.
    #[test]
    fn s256_matches_rfc7636_appendix_b_vector() {
        let pkce = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string());
        assert_eq!(
            pkce.challenge(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(Pkce::METHOD, "S256");
    }

    #[test]
    fn generated_verifier_is_within_rfc_length_bounds_and_unique() {
        let a = Pkce::generate().unwrap();
        let b = Pkce::generate().unwrap();
        // RFC 7636 §4.1: 43..=128 characters.
        assert!((43..=128).contains(&a.verifier().len()), "{}", a.verifier());
        assert_ne!(a.verifier(), b.verifier());
        assert_ne!(a.challenge(), b.challenge());
    }

    #[test]
    fn challenge_is_url_safe_and_unpadded() {
        let pkce = Pkce::generate().unwrap();
        assert!(!pkce.challenge().contains('='));
        assert!(!pkce.challenge().contains('+'));
        assert!(!pkce.challenge().contains('/'));
    }

    #[test]
    fn state_comparison_rejects_mismatch_and_length_difference() {
        let s = generate_state().unwrap();
        assert!(state_matches(&s, &s.clone()));
        assert!(!state_matches(&s, &format!("{s}x")));
        assert!(!state_matches(&s, ""));
        let mut flipped = s.clone().into_bytes();
        flipped[0] ^= 0x01;
        assert!(!state_matches(&s, &String::from_utf8(flipped).unwrap()));
    }
}

//! A machine-readable classification of *why* authentication failed.
//!
//! [`AuthFailReason`] is a bounded, redaction-safe vocabulary for auth
//! failures — built for metrics labels, structured logs, and observer
//! callbacks (see [`AuthObserver`](crate::server::AuthObserver)). It never
//! carries token bytes, claim values, or key material; its
//! [`Display`](std::fmt::Display) text is the same safe phrasing surfaced in
//! `401` bodies, and [`AuthFailReason::label`] gives a stable low-cardinality
//! token for a Prometheus label.
//!
//! It is `#[non_exhaustive]`: code that matches on it must include a `_` arm so
//! new reasons can be added without a breaking change.

use std::fmt;

/// Why an authentication attempt failed, as a stable, low-cardinality enum.
///
/// The JWT-level variants mirror the `jsonwebtoken` failure classes (see
/// [`jwt_fail_reason`](crate::server::jwks::jwt_fail_reason)); the remaining
/// variants describe higher-level outcomes from the configured auth pipeline.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthFailReason {
    /// The token's `exp` is in the past (beyond the configured leeway).
    Expired,
    /// The token's `aud` did not match any accepted audience.
    AudienceMismatch,
    /// The token's `iss` did not match the configured issuer.
    IssuerMismatch,
    /// The token's `nbf`/`iat` is in the future (beyond leeway).
    NotYetValid,
    /// The signature did not verify against the issuer's keys.
    InvalidSignature,
    /// The token's algorithm is not in the provider's allow-list.
    AlgorithmNotAllowed,
    /// A required registered claim (`exp`/`aud`/`iss`/…) was absent.
    MissingRequiredClaim,
    /// The token could not be parsed (base64 / JSON / UTF-8 / shape).
    MalformedToken,
    /// No JWKS key matched the token's `kid`.
    UnknownSigningKey,
    /// The token validated but lacked the configured string identity claim.
    MissingIdentityClaim,
    /// Some other token-level rejection (e.g. an `azp` mismatch) with no more
    /// specific classification.
    TokenRejected,
    /// The provider is misconfigured (a server-side fault, not the caller's).
    Misconfigured,
    /// The IdP / JWKS endpoint was unreachable or returned an invalid document
    /// — a server-side fault (typically surfaced as `5xx`), not a credential
    /// rejection.
    ProviderUnavailable,
    /// No configured provider accepted the credential and none produced a more
    /// specific reason (e.g. an unrecognized bearer with no JWT issuer set).
    NoMatchingProvider,
}

impl AuthFailReason {
    /// A stable, low-cardinality `snake_case` token suitable for a metrics
    /// label. It never contains user data and never changes for a given
    /// variant, so it is safe to use as a Prometheus label value.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::AudienceMismatch => "audience_mismatch",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::NotYetValid => "not_yet_valid",
            Self::InvalidSignature => "invalid_signature",
            Self::AlgorithmNotAllowed => "algorithm_not_allowed",
            Self::MissingRequiredClaim => "missing_required_claim",
            Self::MalformedToken => "malformed_token",
            Self::UnknownSigningKey => "unknown_signing_key",
            Self::MissingIdentityClaim => "missing_identity_claim",
            Self::TokenRejected => "token_rejected",
            Self::Misconfigured => "misconfigured",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::NoMatchingProvider => "no_matching_provider",
        }
    }

    /// A short, redaction-safe human phrase for this reason — the same wording
    /// surfaced in `401` bodies. Never contains token bytes or claim values.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Expired => "token expired",
            Self::AudienceMismatch => "token audience mismatch",
            Self::IssuerMismatch => "token issuer mismatch",
            Self::NotYetValid => "token not yet valid",
            Self::InvalidSignature => "token signature invalid",
            Self::AlgorithmNotAllowed => "signing algorithm not allowed",
            Self::MissingRequiredClaim => "token missing required claim",
            Self::MalformedToken => "malformed token",
            Self::UnknownSigningKey => "unknown signing key",
            Self::MissingIdentityClaim => "missing identity claim",
            Self::TokenRejected => "token rejected",
            Self::Misconfigured => "auth provider misconfigured",
            Self::ProviderUnavailable => "auth provider unavailable",
            Self::NoMatchingProvider => "no matching auth provider",
        }
    }

    /// Whether this is a server-side fault (`5xx`-class) rather than a caller
    /// credential problem (`4xx`-class). Useful to avoid alerting on the steady
    /// background of normal credential rejections.
    pub fn is_server_fault(&self) -> bool {
        matches!(self, Self::Misconfigured | Self::ProviderUnavailable)
    }
}

impl fmt::Display for AuthFailReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_stable_snake_case_and_unique() {
        let all = [
            AuthFailReason::Expired,
            AuthFailReason::AudienceMismatch,
            AuthFailReason::IssuerMismatch,
            AuthFailReason::NotYetValid,
            AuthFailReason::InvalidSignature,
            AuthFailReason::AlgorithmNotAllowed,
            AuthFailReason::MissingRequiredClaim,
            AuthFailReason::MalformedToken,
            AuthFailReason::UnknownSigningKey,
            AuthFailReason::MissingIdentityClaim,
            AuthFailReason::TokenRejected,
            AuthFailReason::Misconfigured,
            AuthFailReason::ProviderUnavailable,
            AuthFailReason::NoMatchingProvider,
        ];
        let mut seen = std::collections::HashSet::new();
        for r in all {
            let label = r.label();
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "label {label:?} is not snake_case"
            );
            assert!(seen.insert(label), "duplicate label {label:?}");
        }
    }

    #[test]
    fn display_matches_message_and_is_redaction_safe() {
        // Display is the safe phrase; no variant leaks structured detail.
        assert_eq!(AuthFailReason::Expired.to_string(), "token expired");
        assert_eq!(
            AuthFailReason::AudienceMismatch.to_string(),
            "token audience mismatch"
        );
    }

    #[test]
    fn server_faults_are_classified() {
        assert!(AuthFailReason::ProviderUnavailable.is_server_fault());
        assert!(AuthFailReason::Misconfigured.is_server_fault());
        assert!(!AuthFailReason::Expired.is_server_fault());
        assert!(!AuthFailReason::NoMatchingProvider.is_server_fault());
    }
}

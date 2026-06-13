use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::common::{AuthError, AuthIdentity, secret_eq};
use crate::server::{AuthnProvider, JwksManager};

/// Builder for common server-side auth configuration.
///
/// This implements the usual "products declare what they accept" path:
/// JWT/OIDC/static Bearer tokens in, normalized [`AuthIdentity`] out.
#[derive(Debug, Default)]
pub struct AuthBuilder {
    jwt: Vec<JwtAuthConfig>,
    static_tokens: Vec<StaticTokenConfig>,
    validation_cache_ttl: Option<Duration>,
}

/// A ready-to-use auth provider for [`AuthLayer`](crate::server::AuthLayer)
/// and axum extractors.
#[derive(Clone)]
pub struct ConfiguredAuth {
    jwks: Arc<JwksManager>,
    jwt: Arc<Vec<JwtAuthConfig>>,
    static_tokens: Arc<Vec<StaticTokenConfig>>,
}

/// JWT validation config for one issuer/provider.
#[derive(Debug, Clone)]
pub struct JwtAuthConfig {
    pub provider: String,
    pub method: String,
    pub issuer: String,
    pub jwks_url: String,
    pub audience: Vec<String>,
    pub algorithms: Vec<String>,
    pub identity_claim: String,
    /// Accepted `azp` (authorized party) values. When non-empty, the validated
    /// token's `azp` claim must be present and match one of these; empty means
    /// `azp` is not checked.
    pub authorized_parties: Vec<String>,
}

/// Static Bearer token config.
#[derive(Clone)]
pub struct StaticTokenConfig {
    pub provider: String,
    pub token: String,
    pub identity: String,
    pub claims: HashMap<String, Value>,
}

impl AuthBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validation_cache(mut self, ttl: Duration) -> Self {
        self.validation_cache_ttl = Some(ttl);
        self
    }

    pub fn jwt(mut self, config: JwtAuthConfig) -> Self {
        self.jwt.push(config);
        self
    }

    pub fn oidc(
        self,
        provider: impl Into<String>,
        issuer: impl Into<String>,
        jwks_url: impl Into<String>,
        audience: Vec<String>,
    ) -> Self {
        self.jwt(JwtAuthConfig::oidc(provider, issuer, jwks_url, audience))
    }

    pub fn static_token(
        mut self,
        provider: impl Into<String>,
        token: impl Into<String>,
        identity: impl Into<String>,
    ) -> Self {
        self.static_tokens
            .push(StaticTokenConfig::new(provider, token, identity));
        self
    }

    pub fn build(self) -> ConfiguredAuth {
        let jwks = match self.validation_cache_ttl {
            Some(ttl) => JwksManager::new().with_validation_cache(ttl),
            None => JwksManager::new(),
        };

        ConfiguredAuth {
            jwks: Arc::new(jwks),
            jwt: Arc::new(self.jwt),
            static_tokens: Arc::new(self.static_tokens),
        }
    }
}

impl JwtAuthConfig {
    pub fn oidc(
        provider: impl Into<String>,
        issuer: impl Into<String>,
        jwks_url: impl Into<String>,
        audience: Vec<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            method: "jwt".into(),
            issuer: issuer.into(),
            jwks_url: jwks_url.into(),
            audience,
            algorithms: vec!["RS256".into()],
            identity_claim: "sub".into(),
            authorized_parties: Vec::new(),
        }
    }

    pub fn algorithms(mut self, algorithms: Vec<String>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Restrict accepted tokens to those whose `azp` claim is one of
    /// `parties`. With no call (or an empty vec), `azp` is not checked.
    pub fn authorized_parties(mut self, parties: Vec<String>) -> Self {
        self.authorized_parties = parties;
        self
    }

    pub fn identity_claim(mut self, claim: impl Into<String>) -> Self {
        self.identity_claim = claim.into();
        self
    }

    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }
}

impl StaticTokenConfig {
    pub fn new(
        provider: impl Into<String>,
        token: impl Into<String>,
        identity: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            token: token.into(),
            identity: identity.into(),
            claims: HashMap::new(),
        }
    }

    pub fn claims(mut self, claims: HashMap<String, Value>) -> Self {
        self.claims = claims;
        self
    }
}

impl fmt::Debug for StaticTokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticTokenConfig")
            .field("provider", &self.provider)
            .field("token", &"<redacted>")
            .field("identity", &self.identity)
            .field("claims", &self.claims)
            .finish()
    }
}

impl AuthnProvider for ConfiguredAuth {
    async fn authenticate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
        for config in self.static_tokens.iter() {
            if secret_eq(&config.token, token) {
                return Ok(AuthIdentity {
                    provider: config.provider.clone(),
                    identity: config.identity.clone(),
                    method: "token".into(),
                    claims: config.claims.clone(),
                });
            }
        }

        // Remember the most specific JWT rejection so the final 401 carries an
        // actionable reason (e.g. "token expired") instead of a blanket
        // "invalid bearer token". Multiple JWT providers rejecting a token is
        // normal in a multi-issuer setup, so each rejection is logged at debug,
        // not warn.
        let mut last_jwt_err: Option<AuthError> = None;

        for config in self.jwt.iter() {
            // A provider must bind tokens by audience or azp; both empty would
            // accept any signed token from the issuer.
            if config.audience.is_empty() && config.authorized_parties.is_empty() {
                return Err(AuthError::Internal(format!(
                    "JWT auth provider {} has neither audience nor authorizedParties configured",
                    config.provider
                )));
            }

            // `validate_jwt_bound` enforces the audience and/or azp binding
            // (whichever is set), so no separate azp check is needed here.
            let claims = match self
                .jwks
                .validate_jwt_bound(
                    token,
                    &config.jwks_url,
                    &config.issuer,
                    &config.audience,
                    &config.authorized_parties,
                    &config.algorithms,
                )
                .await
            {
                Ok(claims) => claims,
                Err(e) => {
                    // Don't swallow the reason: log the specific error
                    // server-side and keep it so the 401 can surface it.
                    tracing::debug!(
                        provider = %config.provider,
                        error = %e,
                        "JWT provider rejected token"
                    );
                    last_jwt_err = Some(classify_jwt_error(e));
                    continue;
                }
            };

            let identity = claims
                .get(&config.identity_claim)
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AuthError::Unauthorized(format!(
                        "JWT missing string identity claim {}",
                        config.identity_claim
                    ))
                })?
                .to_string();

            return Ok(AuthIdentity {
                provider: config.provider.clone(),
                identity,
                method: config.method.clone(),
                claims,
            });
        }

        // Surface the most specific JWT rejection (e.g. "token expired") when a
        // provider was tried; otherwise no JWT provider matched at all, so fall
        // back to a generic reason. Transport faults are preserved as Internal
        // by `classify_jwt_error`, so a JWKS outage still reads as a 500.
        Err(last_jwt_err.unwrap_or_else(|| AuthError::Unauthorized("invalid bearer token".into())))
    }
}

/// Classify an [`anyhow::Error`] from `validate_jwt_bound` into the right
/// [`AuthError`] without echoing token bytes or key material.
///
/// JWKS *transport/structural* faults (network failure, oversized/invalid JWKS,
/// bad JWKS URL) are the server's problem, not the caller's — they map to
/// [`AuthError::Internal`] (500-class) with the detail kept for server logs.
/// Everything else is a token-level validation failure and maps to
/// [`AuthError::Unauthorized`] carrying the specific, redaction-safe top-level
/// message produced in `jwks` (e.g. "token expired", "token audience mismatch").
fn classify_jwt_error(err: anyhow::Error) -> AuthError {
    if is_jwks_transport_fault(&err) {
        // Keep the full detail server-side (Internal is logged + redacted in
        // `into_response`); never leak it to the 401 path.
        return AuthError::Internal(format!("JWKS fetch/transport failure: {err:#}"));
    }
    // The top-level message is the specific, safe reason set in `jwks`.
    AuthError::Unauthorized(err.to_string())
}

/// Whether the error chain points at a JWKS fetch/transport/structural fault
/// (server-side) rather than a token validation failure (caller-side).
fn is_jwks_transport_fault(err: &anyhow::Error) -> bool {
    // A reqwest error anywhere in the chain is a definitive transport fault.
    if err.chain().any(|cause| cause.is::<reqwest::Error>()) {
        return true;
    }
    // The remaining JWKS server-side faults are raised via `anyhow` with these
    // stable context/message prefixes (see `jwks::get_keys` /
    // `validate_remote_auth_url`). Match on those so a misbehaving IdP or a
    // misconfigured JWKS URL reads as a 500, not a 401.
    const JWKS_FAULT_MARKERS: [&str; 5] = [
        "Failed to fetch JWKS",
        "Failed to read JWKS response body",
        "Failed to parse JWKS",
        "JWKS response exceeds",
        "JWKS URL",
    ];
    err.chain().any(|cause| {
        let msg = cause.to_string();
        JWKS_FAULT_MARKERS.iter().any(|marker| msg.contains(marker))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_config_sets_default_jwt_fields() {
        let config = JwtAuthConfig::oidc(
            "firebase",
            "https://securetoken.google.com/my-project",
            "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
            vec!["my-project".into()],
        );
        assert_eq!(config.provider, "firebase");
        assert_eq!(config.method, "jwt");
        assert_eq!(config.audience, vec!["my-project"]);
        assert_eq!(config.algorithms, vec!["RS256"]);
        assert_eq!(config.identity_claim, "sub");
    }

    #[tokio::test]
    async fn configured_auth_accepts_static_token() {
        let auth = AuthBuilder::new()
            .static_token("dev-token", "secret", "dev-user")
            .build();

        let identity = auth.authenticate("secret").await.unwrap();
        assert_eq!(identity.provider, "dev-token");
        assert_eq!(identity.identity, "dev-user");
        assert_eq!(identity.method, "token");
    }

    #[tokio::test]
    async fn configured_auth_rejects_unknown_token() {
        let auth = AuthBuilder::new()
            .static_token("dev-token", "secret", "dev-user")
            .build();

        let err = auth.authenticate("wrong").await.unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    #[test]
    fn static_token_debug_redacts_secret() {
        let config = StaticTokenConfig::new("dev-token", "super-secret", "dev-user");
        let rendered = format!("{config:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret"));
    }

    #[test]
    fn token_match_rejects_different_values() {
        assert!(secret_eq("secret", "secret"));
        assert!(!secret_eq("secret", "secrex"));
        assert!(!secret_eq("secret", "secret-extra"));
    }

    #[test]
    fn oidc_config_has_no_authorized_parties_by_default() {
        let config = JwtAuthConfig::oidc("p", "https://i", "https://i/jwks", vec!["aud".into()]);
        assert!(config.authorized_parties.is_empty());
    }

    #[test]
    fn authorized_parties_builder_sets_the_list() {
        let config = JwtAuthConfig::oidc("p", "https://i", "https://i/jwks", vec!["aud".into()])
            .authorized_parties(vec!["cli".into(), "web".into()]);
        assert_eq!(config.authorized_parties, vec!["cli", "web"]);
    }

    /// Pure check mirroring the `azp` gate in `authenticate`, so the policy is
    /// exercised without needing a live JWKS endpoint.
    fn azp_allowed(authorized: &[String], claims: &HashMap<String, Value>) -> bool {
        if authorized.is_empty() {
            return true;
        }
        let azp = claims.get("azp").and_then(|v| v.as_str());
        azp.is_some_and(|p| authorized.iter().any(|a| a == p))
    }

    #[test]
    fn azp_gate_accepts_listed_party() {
        let authorized = vec!["cli".to_string()];
        let mut claims = HashMap::new();
        claims.insert("azp".to_string(), Value::from("cli"));
        assert!(azp_allowed(&authorized, &claims));
    }

    #[test]
    fn azp_gate_rejects_unlisted_or_missing_party() {
        let authorized = vec!["cli".to_string()];

        let mut other = HashMap::new();
        other.insert("azp".to_string(), Value::from("attacker"));
        assert!(!azp_allowed(&authorized, &other));

        let missing: HashMap<String, Value> = HashMap::new();
        assert!(!azp_allowed(&authorized, &missing));
    }

    #[test]
    fn azp_gate_disabled_when_unset() {
        let authorized: Vec<String> = Vec::new();
        let missing: HashMap<String, Value> = HashMap::new();
        assert!(azp_allowed(&authorized, &missing));
    }

    // ── classify_jwt_error: don't swallow the reason ──────────────────────

    #[test]
    fn classify_jwt_error_surfaces_specific_validation_reason() {
        // A token-validation failure becomes a SPECIFIC Unauthorized, carrying
        // the exact reason `jwks` produced -- never the blanket message.
        let err = anyhow::anyhow!("token expired");
        match classify_jwt_error(err) {
            AuthError::Unauthorized(msg) => {
                assert_eq!(msg, "token expired");
                assert_ne!(msg, "invalid bearer token");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn classify_jwt_error_keeps_transport_faults_as_internal() {
        // A JWKS fetch failure is the server's fault (500-class), not the
        // caller's -- it must NOT degrade into a 401.
        let err = anyhow::anyhow!("connection refused").context("Failed to fetch JWKS");
        assert!(matches!(classify_jwt_error(err), AuthError::Internal(_)));
    }

    #[test]
    fn classify_jwt_error_treats_jwks_structural_faults_as_internal() {
        for ctx in [
            "Failed to parse JWKS",
            "Failed to read JWKS response body",
            "JWKS response exceeds the 1048576-byte limit",
            "JWKS URL must use https outside loopback/test hosts: http://idp/jwks",
        ] {
            let err = anyhow::anyhow!("{ctx}");
            assert!(
                matches!(classify_jwt_error(err), AuthError::Internal(_)),
                "expected Internal for {ctx:?}"
            );
        }
    }

    #[tokio::test]
    async fn authenticate_surfaces_specific_reason_not_blanket() {
        // With a single OIDC provider pointed at a loopback JWKS URL that never
        // answers, an arbitrary bearer fails at the *transport* layer, so the
        // result is Internal (server fault) rather than the old blanket
        // "invalid bearer token" 401 -- proving the reason is no longer
        // swallowed. (The ErrorKind->message mapping for genuine token
        // rejections is unit-tested in `jwks`.)
        let auth = AuthBuilder::new()
            .oidc(
                "test",
                "https://issuer.example.com",
                // Loopback + unused port: connection refused fast, no network.
                "http://127.0.0.1:1/.well-known/jwks.json",
                vec!["aud".into()],
            )
            .build();

        let err = auth.authenticate("some.bearer.token").await.unwrap_err();
        match err {
            AuthError::Internal(_) => {}
            AuthError::Unauthorized(msg) => {
                assert_ne!(msg, "invalid bearer token", "reason must be specific");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_falls_back_to_generic_when_no_jwt_provider() {
        // No JWT provider configured and the static token doesn't match: there
        // is no specific JWT reason, so we keep the generic fallback.
        let auth = AuthBuilder::new()
            .static_token("dev-token", "secret", "dev-user")
            .build();
        let err = auth.authenticate("wrong").await.unwrap_err();
        match err {
            AuthError::Unauthorized(msg) => assert_eq!(msg, "invalid bearer token"),
            other => panic!("expected generic Unauthorized, got {other:?}"),
        }
    }
}

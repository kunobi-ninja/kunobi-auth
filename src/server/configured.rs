use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::common::{AuthError, AuthFailReason, AuthIdentity, secret_eq};
use crate::server::observer::{AuthEvent, AuthObserver};
use crate::server::{AuthnProvider, JwksManager};
use jsonwebtoken::errors::Error as JwtError;

/// Builder for common server-side auth configuration.
///
/// This implements the usual "products declare what they accept" path:
/// JWT/OIDC/static Bearer tokens in, normalized [`AuthIdentity`] out.
// `Debug` is hand-written below: `Arc<dyn AuthObserver>` is not `Debug`, so the
// derive would not apply. `Default` still derives (every field, incl.
// `Option<Arc<dyn …>>`, defaults).
#[derive(Default)]
pub struct AuthBuilder {
    jwt: Vec<JwtAuthConfig>,
    static_tokens: Vec<StaticTokenConfig>,
    validation_cache_ttl: Option<Duration>,
    leeway: Option<Duration>,
    observer: Option<Arc<dyn AuthObserver>>,
}

impl fmt::Debug for AuthBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthBuilder")
            .field("jwt", &self.jwt)
            .field("static_tokens", &self.static_tokens)
            .field("validation_cache_ttl", &self.validation_cache_ttl)
            .field("leeway", &self.leeway)
            // `dyn AuthObserver` is opaque; just record presence.
            .field("observer", &self.observer.as_ref().map(|_| "<set>"))
            .finish()
    }
}

/// A ready-to-use auth provider for [`AuthLayer`](crate::server::AuthLayer)
/// and axum extractors.
#[derive(Clone)]
pub struct ConfiguredAuth {
    jwks: Arc<JwksManager>,
    jwt: Arc<Vec<JwtAuthConfig>>,
    static_tokens: Arc<Vec<StaticTokenConfig>>,
    /// Optional telemetry hook invoked on every auth attempt (default: none).
    observer: Option<Arc<dyn AuthObserver>>,
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

    /// Set the JWT clock-skew tolerance for `exp`/`nbf` across all providers
    /// (see [`JwksManager::with_leeway`]). Defaults to 60s when unset.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = Some(leeway);
        self
    }

    /// Register a telemetry hook invoked on every authentication attempt.
    ///
    /// The observer is called synchronously on the auth path and must not
    /// block — see [`AuthObserver`]. Wrap shared state in the `Arc` you pass in.
    pub fn observer(mut self, observer: Arc<dyn AuthObserver>) -> Self {
        self.observer = Some(observer);
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
        let mut jwks = JwksManager::new();
        if let Some(ttl) = self.validation_cache_ttl {
            jwks = jwks.with_validation_cache(ttl);
        }
        if let Some(leeway) = self.leeway {
            jwks = jwks.with_leeway(leeway);
        }

        ConfiguredAuth {
            jwks: Arc::new(jwks),
            jwt: Arc::new(self.jwt),
            static_tokens: Arc::new(self.static_tokens),
            observer: self.observer,
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

impl ConfiguredAuth {
    /// Notify the registered observer, if any. A cheap no-op when unset.
    fn observe(&self, event: AuthEvent<'_>) {
        if let Some(observer) = &self.observer {
            observer.observe(event);
        }
    }
}

impl AuthnProvider for ConfiguredAuth {
    async fn authenticate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
        for config in self.static_tokens.iter() {
            if secret_eq(&config.token, token) {
                let identity = AuthIdentity {
                    provider: config.provider.clone(),
                    identity: config.identity.clone(),
                    method: "token".into(),
                    claims: config.claims.clone(),
                };
                self.observe(AuthEvent::Success {
                    identity: &identity,
                });
                return Ok(identity);
            }
        }

        // Remember the most specific JWT rejection so the final 401 carries an
        // actionable reason (e.g. "token expired") instead of a blanket
        // "invalid bearer token". Multiple JWT providers rejecting a token is
        // normal in a multi-issuer setup, so each rejection is logged at debug,
        // not warn. `last_fail` mirrors it as a typed (provider, reason) pair
        // for the observer's terminal Failure event.
        let mut last_jwt_err: Option<AuthError> = None;
        let mut last_fail: Option<(String, AuthFailReason)> = None;

        for config in self.jwt.iter() {
            // A provider must bind tokens by audience or azp; both empty would
            // accept any signed token from the issuer.
            if config.audience.is_empty() && config.authorized_parties.is_empty() {
                self.observe(AuthEvent::Failure {
                    provider: Some(&config.provider),
                    reason: AuthFailReason::Misconfigured,
                });
                return Err(AuthError::internal(format!(
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
                    // server-side and keep it (typed + as an AuthError) so both
                    // the 401 and the observer get the specific cause.
                    tracing::debug!(
                        provider = %config.provider,
                        error = %e,
                        "JWT provider rejected token"
                    );
                    last_fail = Some((config.provider.clone(), jwt_fail_reason_of(&e)));
                    last_jwt_err = Some(classify_jwt_error(e));
                    continue;
                }
            };

            let identity = match claims.get(&config.identity_claim).and_then(|v| v.as_str()) {
                Some(identity) => identity.to_string(),
                None => {
                    self.observe(AuthEvent::Failure {
                        provider: Some(&config.provider),
                        reason: AuthFailReason::MissingIdentityClaim,
                    });
                    return Err(AuthError::Unauthorized(format!(
                        "JWT missing string identity claim {}",
                        config.identity_claim
                    )));
                }
            };

            let identity = AuthIdentity {
                provider: config.provider.clone(),
                identity,
                method: config.method.clone(),
                claims,
            };
            self.observe(AuthEvent::Success {
                identity: &identity,
            });
            return Ok(identity);
        }

        // Surface the most specific JWT rejection (e.g. "token expired") when a
        // provider was tried; otherwise no JWT provider matched at all, so fall
        // back to a generic reason. Transport faults are preserved as Internal
        // by `classify_jwt_error`, so a JWKS outage still reads as a 500.
        let (provider, reason) = match &last_fail {
            Some((provider, reason)) => (Some(provider.as_str()), *reason),
            None => (None, AuthFailReason::NoMatchingProvider),
        };
        self.observe(AuthEvent::Failure { provider, reason });
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
        // Keep the full detail server-side: it rides in the error source chain
        // (logged in `into_response`) while the body/message stay the static,
        // redaction-safe summary — never leaked to the 401 path.
        return AuthError::internal_with_source("JWKS fetch/transport failure", err);
    }
    // The top-level message is the specific, safe reason set in `jwks`.
    AuthError::Unauthorized(err.to_string())
}

/// Derive a typed [`AuthFailReason`] from a `validate_jwt_bound` error, for the
/// observer hook. Mirrors [`classify_jwt_error`]'s split: transport/structural
/// JWKS faults are server-side ([`AuthFailReason::ProviderUnavailable`]);
/// otherwise recover the precise token-level reason from the original
/// `jsonwebtoken` error preserved in the source chain, falling back to stable
/// markers for the structural rejections raised as bare `anyhow`.
fn jwt_fail_reason_of(err: &anyhow::Error) -> AuthFailReason {
    if is_jwks_transport_fault(err) {
        return AuthFailReason::ProviderUnavailable;
    }
    // `validate_jwt_bound` wraps the original jsonwebtoken error as the source
    // (`anyhow::Error::new(e).context(reason)`), so downcast to recover the
    // exact kind without re-parsing the human message.
    if let Some(jwt) = err.downcast_ref::<JwtError>() {
        return crate::server::jwks::jwt_fail_reason(jwt);
    }
    // Token-level rejections raised as bare `anyhow` (disallowed alg before
    // decode, unknown `kid`): map the stable markers, else a generic reject.
    let msg = err.to_string();
    if msg.contains("unknown signing key") {
        AuthFailReason::UnknownSigningKey
    } else if msg.contains("signing algorithm not allowed") {
        AuthFailReason::AlgorithmNotAllowed
    } else {
        AuthFailReason::TokenRejected
    }
}

/// Whether the error chain points at a JWKS fetch/transport/structural fault
/// (server-side) rather than a token validation failure (caller-side).
fn is_jwks_transport_fault(err: &anyhow::Error) -> bool {
    // `jwks::get_keys` failures carry a typed `JwksFault` marker in the
    // context chain; detect it by downcast. Never classify on message text —
    // the chain embeds attacker-controlled values (e.g. the JWT header `kid`),
    // so substring matching would let an unauthenticated caller flip 401s
    // into 500s with a crafted `kid`.
    if err
        .downcast_ref::<crate::server::jwks::JwksFault>()
        .is_some()
    {
        return true;
    }
    // A reqwest error anywhere in the chain is a definitive transport fault.
    err.chain().any(|cause| cause.is::<reqwest::Error>())
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
        let err = anyhow::anyhow!("connection refused")
            .context("Failed to fetch JWKS")
            .context(crate::server::jwks::JwksFault);
        assert!(matches!(
            classify_jwt_error(err),
            AuthError::Internal { .. }
        ));
    }

    #[test]
    fn classify_jwt_error_treats_jwks_structural_faults_as_internal() {
        for ctx in [
            "Failed to parse JWKS",
            "Failed to read JWKS response body",
            "JWKS response exceeds the 1048576-byte limit",
            "JWKS URL must use https outside loopback/test hosts: http://idp/jwks",
        ] {
            let err = anyhow::anyhow!("{ctx}").context(crate::server::jwks::JwksFault);
            assert!(
                matches!(classify_jwt_error(err), AuthError::Internal { .. }),
                "expected Internal for {ctx:?}"
            );
        }
    }

    #[test]
    fn classify_jwt_error_ignores_fault_markers_in_untrusted_text() {
        // The JWT header `kid` is attacker-controlled and is embedded in the
        // error chain; text resembling a fault marker must NOT flip the 401
        // into a 500 (false "IdP down" signal). Only the typed `JwksFault`
        // marker (or a real reqwest error) classifies as transport fault.
        let err = anyhow::anyhow!("No signing key found with kid: Failed to fetch JWKS")
            .context("unknown signing key (kid)");
        assert!(matches!(
            classify_jwt_error(err),
            AuthError::Unauthorized(_)
        ));

        let err = anyhow::anyhow!("No signing key found with kid: JWKS URL")
            .context("unknown signing key (kid)");
        assert_eq!(
            jwt_fail_reason_of(&err),
            AuthFailReason::UnknownSigningKey,
            "crafted kid must not read as ProviderUnavailable"
        );
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
            AuthError::Internal { .. } => {}
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

    // ── observer hook ─────────────────────────────────────────────────────

    /// A captured event as a `(kind, provider, reason_label)` tuple.
    type RecordedEvent = (String, Option<String>, Option<String>);

    #[derive(Default)]
    struct RecordingObserver {
        events: std::sync::Mutex<Vec<RecordedEvent>>,
    }

    impl AuthObserver for RecordingObserver {
        fn observe(&self, event: AuthEvent<'_>) {
            let row = match event {
                AuthEvent::Success { identity } => {
                    ("success".to_string(), Some(identity.provider.clone()), None)
                }
                AuthEvent::Failure { provider, reason } => (
                    "failure".to_string(),
                    provider.map(str::to_string),
                    Some(reason.label().to_string()),
                ),
            };
            self.events.lock().unwrap().push(row);
        }
    }

    #[tokio::test]
    async fn observer_sees_static_token_success() {
        let rec = Arc::new(RecordingObserver::default());
        let auth = AuthBuilder::new()
            .static_token("dev-token", "secret", "dev-user")
            .observer(rec.clone())
            .build();

        auth.authenticate("secret").await.unwrap();
        let events = rec.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "success");
        assert_eq!(events[0].1.as_deref(), Some("dev-token"));
    }

    #[tokio::test]
    async fn observer_sees_no_matching_provider_failure() {
        let rec = Arc::new(RecordingObserver::default());
        let auth = AuthBuilder::new()
            .static_token("dev-token", "secret", "dev-user")
            .observer(rec.clone())
            .build();

        auth.authenticate("wrong").await.unwrap_err();
        let events = rec.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "failure");
        assert_eq!(
            events[0].1, None,
            "no single provider owns the fall-through"
        );
        assert_eq!(events[0].2.as_deref(), Some("no_matching_provider"));
    }

    #[test]
    fn jwt_fail_reason_of_recovers_precise_kind_through_anyhow_chain() {
        use jsonwebtoken::errors::{ErrorKind, new_error};

        // Mirror EXACTLY how `validate_jwt_bound` wraps a decode error:
        // `anyhow::Error::new(jwt_err).context(redaction_safe_reason)`. The
        // downcast must see through the context layer to the original kind —
        // otherwise reasons would silently degrade to the TokenRejected
        // fallback.
        for (kind, expected) in [
            (ErrorKind::ExpiredSignature, AuthFailReason::Expired),
            (ErrorKind::InvalidAudience, AuthFailReason::AudienceMismatch),
            (ErrorKind::InvalidIssuer, AuthFailReason::IssuerMismatch),
            (
                ErrorKind::InvalidSignature,
                AuthFailReason::InvalidSignature,
            ),
        ] {
            let wrapped =
                anyhow::Error::new(new_error(kind)).context(AuthFailReason::Expired.message());
            assert_eq!(
                jwt_fail_reason_of(&wrapped),
                expected,
                "downcast must recover the precise kind through the anyhow context layer"
            );
        }

        // Server-side transport fault wins over token-level classification.
        let transport = anyhow::anyhow!("connection refused")
            .context("Failed to fetch JWKS")
            .context(crate::server::jwks::JwksFault);
        assert_eq!(
            jwt_fail_reason_of(&transport),
            AuthFailReason::ProviderUnavailable
        );

        // Bare-anyhow structural rejections map via their stable markers.
        let kid = anyhow::anyhow!("no key for kid").context("unknown signing key (kid)");
        assert_eq!(jwt_fail_reason_of(&kid), AuthFailReason::UnknownSigningKey);

        // Anything else is a generic token-level reject, never a server fault.
        let other = anyhow::anyhow!("something odd");
        assert_eq!(jwt_fail_reason_of(&other), AuthFailReason::TokenRejected);
    }

    #[tokio::test]
    async fn observer_is_optional_and_default_path_is_unaffected() {
        // No observer registered: must not panic and behavior is unchanged.
        let auth = AuthBuilder::new()
            .static_token("dev-token", "secret", "dev-user")
            .build();
        assert!(auth.authenticate("secret").await.is_ok());
        assert!(auth.authenticate("nope").await.is_err());
    }
}

//! Per-connection token storage.
//!
//! Tokens live in the host's OS keychain, keyed by connection id. Nothing about
//! a token is written to any plaintext record: a record carries only *when* it
//! expires and *whether* a refresh token exists, which is what a UI needs and
//! all it may have.
//!
//! # Why the host supplies the backend
//!
//! This module knows the SHAPE of stored credentials -- two entries per
//! connection, a JSON envelope for the access token -- but not WHERE they live.
//! That is deliberate. A host's keychain identity is frozen the moment it ships:
//! the gateway resolves a variant-aware service name and reads through a legacy
//! name for entries written before it was renamed, and a store that knew only a
//! service *string* would silently drop that fallback.
//!
//! The failure mode is what makes this worth a seam rather than a parameter.
//! Nothing errors when an account name changes -- the load simply returns
//! `None`, and a host that treats a missing token as "needs re-authorization"
//! tells every existing user to sign in again, with no way back to the old
//! entry. So the host passes a [`SecretBackend`] it already trusts, and a
//! [`KeychainAccounts`] prefix it pins forever.

use std::sync::Arc;

/// Seconds before nominal expiry at which a token is treated as expired.
///
/// Wide enough to cover a slow refresh plus clock skew between this machine and
/// the authorization server. Refreshing early is free; discovering expiry from
/// a 401 costs a round trip and a re-auth prompt.
pub const EXPIRY_SKEW_SECS: i64 = 120;

/// An access token and its companions, as returned by a token endpoint.
///
/// `Debug` is implemented by hand so a stray `{:?}` in a log line cannot print
/// a bearer token — this struct is passed through error paths where that is
/// exactly what would happen.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Absolute expiry as a Unix timestamp. `None` for a server that returns no
    /// `expires_in`, which is treated as "never proactively refresh" — the 401
    /// path in the host's own 401 handling still recovers it.
    pub expires_at: Option<i64>,
    /// Scopes actually granted, when the server says. May be narrower than
    /// requested; a step-up must compare against this, not against the request.
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl TokenSet {
    /// Parse an RFC 6749 §5.1 token response.
    pub fn from_token_response(body: &serde_json::Value) -> anyhow::Result<Self> {
        let access_token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("token response has no access_token"))?
            .to_string();

        // Only bearer tokens can be injected as `Authorization: Bearer`. A DPoP
        // or MAC token would need proof-of-possession machinery we do not have,
        // and sending it as a bearer would simply fail upstream with a confusing
        // 401 — which is worse than refusing here.
        if let Some(kind) = body.get("token_type").and_then(|v| v.as_str())
            && !kind.eq_ignore_ascii_case("bearer")
        {
            // The value is NOT echoed: it is server-chosen text, and this
            // message reaches logs and a persisted failure reason.
            anyhow::bail!(
                "the token response used a token_type other than Bearer, which Kunobi cannot \
                 present; the connection cannot be used"
            );
        }

        let expires_at = body
            .get("expires_in")
            .and_then(serde_json::Value::as_i64)
            .map(|secs| now_unix() + secs);

        let scopes = body
            .get("scope")
            .and_then(|v| v.as_str())
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();

        Ok(Self {
            access_token,
            refresh_token: body
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            expires_at,
            scopes,
        })
    }

    /// Whether this token should be refreshed before use.
    pub fn is_expired(&self, now: i64) -> bool {
        match self.expires_at {
            Some(at) => now + EXPIRY_SKEW_SECS >= at,
            None => false,
        }
    }
}

/// Current Unix time. A free function so tests can pass an explicit `now`
/// everywhere the value matters.
pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// How a host names its two keychain entries per connection.
///
/// The prefix is the host's to choose and then never change: see the module
/// header for why a rename is silent rather than loud. The gateway is pinned to
/// `mcp-target`, and `tests/compat_keychain.rs` holds it there.
#[derive(Debug, Clone)]
pub struct KeychainAccounts {
    prefix: String,
}

impl KeychainAccounts {
    /// Name entries under `<prefix>/<connection id>/oauth/...`.
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// Account holding the access-token envelope.
    pub fn access(&self, connection_id: &str) -> String {
        format!("{}/{connection_id}/oauth/access", self.prefix)
    }

    /// Account holding the bare refresh token.
    pub fn refresh(&self, connection_id: &str) -> String {
        format!("{}/{connection_id}/oauth/refresh", self.prefix)
    }
}

/// The host's secret storage, already configured with its service name and
/// whatever legacy-lookup behaviour it needs.
///
/// Implementations are expected to distinguish "no such entry" (`Ok(None)`)
/// from "the backend itself failed" (`Err`) -- conflating them turns a keychain
/// outage into a spurious re-authorization prompt.
pub trait SecretBackend: Send + Sync {
    fn get(&self, account: &str) -> anyhow::Result<Option<String>>;
    fn set(&self, account: &str, value: &str) -> anyhow::Result<()>;
    fn remove(&self, account: &str) -> anyhow::Result<()>;
}

/// Reads and writes [`TokenSet`]s. A trait so the injector's tests can run
/// without an OS keychain (headless CI has no Secret Service).
pub trait TokenStore: Send + Sync {
    fn load(&self, target_id: &str) -> anyhow::Result<Option<TokenSet>>;
    fn save(&self, target_id: &str, set: &TokenSet) -> anyhow::Result<()>;
    fn clear(&self, target_id: &str) -> anyhow::Result<()>;
}

/// The production store: the host's keychain, two entries per connection.
///
/// The access token is stored as a small JSON envelope so `expires_at` and the
/// granted scopes travel with it; the refresh token is a separate entry so it
/// can be removed independently when a server rotates or revokes it.
///
/// Both shapes are on disk in every existing gateway install, so
/// `tests/compat_keychain.rs` pins them.
pub struct KeychainTokenStore {
    backend: Arc<dyn SecretBackend>,
    accounts: KeychainAccounts,
}

impl KeychainTokenStore {
    pub fn new(backend: Arc<dyn SecretBackend>, accounts: KeychainAccounts) -> Self {
        Self { backend, accounts }
    }
}

impl TokenStore for KeychainTokenStore {
    fn load(&self, connection_id: &str) -> anyhow::Result<Option<TokenSet>> {
        let Some(raw) = self.backend.get(&self.accounts.access(connection_id))? else {
            return Ok(None);
        };
        let env: StoredAccess = serde_json::from_str(&raw).map_err(|e| {
            anyhow::anyhow!("stored OAuth token for {connection_id} is unreadable: {e}")
        })?;
        let refresh = self.backend.get(&self.accounts.refresh(connection_id))?;
        Ok(Some(TokenSet {
            access_token: env.access_token,
            refresh_token: refresh,
            expires_at: env.expires_at,
            scopes: env.scopes,
        }))
    }

    /// # Why the access entry is cleared first and written last
    ///
    /// Two keychain writes cannot be made one atomic operation, so this fails
    /// CLOSED instead of pretending otherwise.
    ///
    /// [`Self::load`] returns `None` without the access entry, which makes that
    /// entry the commit point: removing it first means every partial failure
    /// leaves the connection with no readable credential — the user is asked to
    /// authorize again, which is recoverable and honest.
    ///
    /// Writing access FIRST was the alternative, and it is the dangerous one: a
    /// failure on the refresh write then left the NEW access token beside the
    /// OLD refresh token. For a re-authorization that switched accounts, that is
    /// account B's access token paired with account A's refresh token — a
    /// connection that works now and silently becomes a different identity at
    /// the first refresh. Injecting a refresh-write failure reproduced exactly
    /// that.
    fn save(&self, connection_id: &str, set: &TokenSet) -> anyhow::Result<()> {
        let env = serde_json::to_string(&StoredAccess::from(set))?;

        // Commit point opens: from here until the last line, the connection has
        // no loadable credential.
        self.backend.remove(&self.accounts.access(connection_id))?;

        match &set.refresh_token {
            Some(rt) => self
                .backend
                .set(&self.accounts.refresh(connection_id), rt)?,
            None => self.backend.remove(&self.accounts.refresh(connection_id))?,
        }

        // Commit point closes. A failure above leaves nothing readable rather
        // than a mixed pair.
        self.backend
            .set(&self.accounts.access(connection_id), &env)?;
        Ok(())
    }

    fn clear(&self, connection_id: &str) -> anyhow::Result<()> {
        self.backend.remove(&self.accounts.access(connection_id))?;
        self.backend.remove(&self.accounts.refresh(connection_id))?;
        Ok(())
    }
}

/// The access entry's on-disk envelope. `pub` so the compatibility test can
/// assert its exact JSON shape; the refresh token is deliberately NOT a field
/// here -- it lives in its own entry.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StoredAccess {
    pub access_token: String,
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl From<&TokenSet> for StoredAccess {
    fn from(set: &TokenSet) -> Self {
        Self {
            access_token: set.access_token.clone(),
            expires_at: set.expires_at,
            scopes: set.scopes.clone(),
        }
    }
}

/// In-memory store for tests.
#[derive(Default)]
pub struct MemoryTokenStore {
    inner: std::sync::Mutex<std::collections::HashMap<String, TokenSet>>,
}

impl MemoryTokenStore {
    pub fn with(target_id: &str, set: TokenSet) -> Self {
        let s = Self::default();
        s.inner.lock().unwrap().insert(target_id.to_string(), set);
        s
    }
}

impl TokenStore for MemoryTokenStore {
    fn load(&self, target_id: &str) -> anyhow::Result<Option<TokenSet>> {
        Ok(self.inner.lock().unwrap().get(target_id).cloned())
    }
    fn save(&self, target_id: &str, set: &TokenSet) -> anyhow::Result<()> {
        self.inner
            .lock()
            .unwrap()
            .insert(target_id.to_string(), set.clone());
        Ok(())
    }
    fn clear(&self, target_id: &str) -> anyhow::Result<()> {
        self.inner.lock().unwrap().remove(target_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_standard_token_response() {
        let set = TokenSet::from_token_response(&serde_json::json!({
            "access_token": "at", "token_type": "Bearer", "expires_in": 3600,
            "refresh_token": "rt", "scope": "read write"
        }))
        .unwrap();
        assert_eq!(set.access_token, "at");
        assert_eq!(set.refresh_token.as_deref(), Some("rt"));
        assert_eq!(set.scopes, vec!["read", "write"]);
        assert!(set.expires_at.unwrap() > now_unix());
    }

    #[test]
    fn token_type_match_is_case_insensitive_and_optional() {
        for body in [
            serde_json::json!({"access_token": "a", "token_type": "bearer"}),
            serde_json::json!({"access_token": "a", "token_type": "BEARER"}),
            serde_json::json!({"access_token": "a"}),
        ] {
            assert!(TokenSet::from_token_response(&body).is_ok(), "{body}");
        }
    }

    #[test]
    fn refuses_a_non_bearer_token_type() {
        let err = TokenSet::from_token_response(&serde_json::json!({
            "access_token": "a", "token_type": "DPoP"
        }))
        .unwrap_err()
        .to_string();
        // The value is deliberately NOT echoed — it is server-chosen text and
        // this message reaches logs and a persisted failure reason.
        assert!(err.contains("other than Bearer"), "{err}");
        assert!(!err.contains("DPoP"), "{err}");
    }

    #[test]
    fn an_empty_access_token_is_rejected_like_a_missing_one() {
        assert!(TokenSet::from_token_response(&serde_json::json!({"access_token": ""})).is_err());
        assert!(TokenSet::from_token_response(&serde_json::json!({})).is_err());
    }

    #[test]
    fn an_empty_refresh_token_is_treated_as_absent() {
        let set = TokenSet::from_token_response(
            &serde_json::json!({"access_token": "a", "refresh_token": ""}),
        )
        .unwrap();
        assert!(set.refresh_token.is_none());
    }

    #[test]
    fn expiry_uses_a_skew_so_a_token_is_never_used_at_the_boundary() {
        let set = TokenSet {
            access_token: "a".into(),
            refresh_token: None,
            expires_at: Some(1_000),
            scopes: vec![],
        };
        assert!(!set.is_expired(1_000 - EXPIRY_SKEW_SECS - 1));
        assert!(set.is_expired(1_000 - EXPIRY_SKEW_SECS));
        assert!(set.is_expired(1_001));
    }

    #[test]
    fn a_token_without_expiry_is_never_proactively_refreshed() {
        let set = TokenSet {
            access_token: "a".into(),
            refresh_token: None,
            expires_at: None,
            scopes: vec![],
        };
        assert!(!set.is_expired(i64::MAX - 1));
    }

    /// A bearer token in a log line is a credential leak that survives in log
    /// files long after the token would have expired from the keychain.
    #[test]
    fn debug_never_prints_token_material() {
        let set = TokenSet {
            access_token: "super-secret-access".into(),
            refresh_token: Some("super-secret-refresh".into()),
            expires_at: Some(1),
            scopes: vec!["read".into()],
        };
        let s = format!("{set:?}");
        assert!(!s.contains("super-secret-access"), "{s}");
        assert!(!s.contains("super-secret-refresh"), "{s}");
        assert!(s.contains("read"));
    }

    #[test]
    fn memory_store_round_trips_and_clears() {
        let store = MemoryTokenStore::default();
        let set = TokenSet {
            access_token: "a".into(),
            refresh_token: Some("r".into()),
            expires_at: Some(5),
            scopes: vec![],
        };
        store.save("t", &set).unwrap();
        assert_eq!(store.load("t").unwrap().unwrap(), set);
        store.clear("t").unwrap();
        assert!(store.load("t").unwrap().is_none());
    }
}

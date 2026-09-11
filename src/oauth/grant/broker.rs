//! Turning a stored [`TokenSet`] into a usable bearer, exactly once at a time.

use std::sync::Arc;

use async_trait::async_trait;

use crate::oauth::discovery::AuthorizationServerMetadata;
use crate::oauth::flow;
use crate::oauth::http_seam::OAuthHttp;
use crate::oauth::tokens::{TokenSet, TokenStore, now_unix};

use super::host::GrantHost;

/// Where a credential consumer gets, and refreshes, an access token.
///
/// A trait so a consumer's failure branches — including "the refresh itself
/// fails" — are drivable without an authorization server or a keychain.
#[async_trait]
pub trait CredentialBroker: Send + Sync {
    /// The token to use now, refreshed if it is at or near expiry.
    async fn access_token(&self, connection_id: &str) -> anyhow::Result<String>;
    /// Force a refresh after an upstream rejection. `Err` ⇒ unrecoverable.
    async fn refresh(&self, connection_id: &str) -> anyhow::Result<String>;
    /// Record that this connection needs the user to authorize again.
    async fn mark_needs_reauth(&self, connection_id: &str, reason: &str);
}

/// The production [`CredentialBroker`]: store-backed, refresh-aware,
/// single-flight.
///
/// One instance per connection, because a token is per connection.
///
/// # Why the refresh lock is not optional
///
/// Without it, N concurrent calls that all find the token expired perform N
/// refreshes. Against a server that **rotates** refresh tokens — which the ones
/// worth supporting do — each exchange invalidates the token the others are
/// about to present, and all but one fail. The surviving token may not even be
/// the one that got stored last.
///
/// Holding the lock is necessary but not sufficient: the winner writes a new
/// token while the losers are queued, so each loser must re-read inside the lock
/// rather than proceed with the refresh token it captured before waiting. That
/// re-read happens inside the locked refresh operation, before checking
/// `only_if_stale_at`.
pub struct RefreshBroker {
    host: Arc<dyn GrantHost>,
    pub connection_id: String,
    pub store: Arc<dyn TokenStore>,
    pub http: Arc<dyn OAuthHttp>,
    pub metadata: AuthorizationServerMetadata,
    client_id: String,
    /// Token-endpoint client secret, for a confidential client.
    ///
    /// Held because a refresh needs it too, not only the initial exchange — a
    /// broker rebuilt after a relaunch without it cannot refresh at all, and
    /// the connection silently degrades to "authorize again" the first time the
    /// access token expires.
    ///
    /// Private, with no accessor: nothing outside this type needs to read it,
    /// and a `pub` field is one `{:?}` away from a log line.
    client_secret: Option<String>,
    /// RFC 8707 audience. `None` for a provider with no resource concept.
    resource: Option<String>,
    scopes: Vec<String>,
    /// Which live resource this broker belongs to, so a late observation from a
    /// replaced one cannot flag the grant that replaced it.
    generation: u64,
    refresh_lock: tokio::sync::Mutex<()>,
    /// The host's per-connection lock, when it has one.
    ///
    /// `refresh_lock` serialises refreshes against EACH OTHER; it says nothing
    /// about a disconnect, a delete, or a replacement grant, because those are
    /// the host's operations. A refresh that reads, spends a round trip, and
    /// writes can therefore overwrite a successor installed while it was away,
    /// or put back a grant that was removed.
    ///
    /// Checking existence before the write is not enough: a SUCCESSOR also
    /// exists, and satisfies the check. Holding the host's lock across the
    /// whole read-modify-write is what actually closes it.
    ///
    /// `None` for a host with no such lock, which then accepts that window.
    commit_lock: Option<Arc<tokio::sync::Mutex<()>>>,
}

/// Constructor arguments, as a struct because there are nine of them and a
/// positional call was already `#[allow(clippy::too_many_arguments)]`.
pub struct RefreshBrokerConfig {
    pub host: Arc<dyn GrantHost>,
    pub connection_id: String,
    pub store: Arc<dyn TokenStore>,
    pub http: Arc<dyn OAuthHttp>,
    pub metadata: AuthorizationServerMetadata,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub resource: Option<String>,
    pub scopes: Vec<String>,
    pub generation: u64,
    /// Supply the same lock the host takes
    /// around disconnect, delete, and grant completion.
    pub commit_lock: Option<Arc<tokio::sync::Mutex<()>>>,
}

impl RefreshBroker {
    pub fn new(config: RefreshBrokerConfig) -> Self {
        Self {
            host: config.host,
            connection_id: config.connection_id,
            store: config.store,
            http: config.http,
            metadata: config.metadata,
            client_id: config.client_id,
            client_secret: config.client_secret,
            resource: config.resource,
            scopes: config.scopes,
            generation: config.generation,
            refresh_lock: tokio::sync::Mutex::new(()),
            commit_lock: config.commit_lock,
        }
    }

    fn load(&self) -> anyhow::Result<TokenSet> {
        self.store
            .load(&self.connection_id)?
            .ok_or_else(|| anyhow::anyhow!("this connection has no stored authorization"))
    }

    /// Refresh under the single-flight lock, re-reading the stored token first
    /// so a caller that lost the race adopts the winner's result instead of
    /// spending a refresh token that is already dead.
    async fn refresh_locked(&self, only_if_stale_at: Option<i64>) -> anyhow::Result<String> {
        let _guard = self.refresh_lock.lock().await;
        // Held across the whole read-modify-write, so a disconnect, a delete or
        // a replacement grant cannot interleave with it.
        let host_guard = match &self.commit_lock {
            Some(lock) => Some(lock.clone().lock_owned().await),
            None => None,
        };
        let current = self.load()?;
        if let Some(now) = only_if_stale_at
            && !current.is_expired(now)
        {
            return Ok(current.access_token);
        }
        let refresh = current.refresh_token.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "the access token has expired and this server issued no refresh token, so the \
                 connection must be authorized again"
            )
        })?;
        let next = flow::refresh_token(
            self.http.as_ref(),
            &self.metadata,
            &self.client_id,
            self.client_secret.as_deref(),
            self.resource.as_deref(),
            &refresh,
            &self.scopes,
        )
        .await?;

        // Belt and braces for a host with no commit lock: a removal that
        // happened while this was on the network must not be undone. It cannot
        // distinguish a SUCCESSOR from the grant this refresh started with —
        // only the host lock above does that.
        if self.store.load(&self.connection_id)?.is_none() {
            anyhow::bail!(
                "this connection's authorization was removed while a refresh was in flight; \
                 the refreshed token was discarded"
            );
        }

        self.store.save(&self.connection_id, &next)?;
        drop(host_guard);
        Ok(next.access_token)
    }
}

#[async_trait]
impl CredentialBroker for RefreshBroker {
    // The `connection_id` arguments are ignored: this broker serves exactly one
    // connection, fixed at construction. Honouring a caller's id instead would
    // let a mismatched call read this connection's token -- which is what
    // `mark_needs_reauth` used to do, flagging whatever id it was handed.
    async fn access_token(&self, _connection_id: &str) -> anyhow::Result<String> {
        let now = now_unix();
        let current = self.load()?;
        if !current.is_expired(now) {
            return Ok(current.access_token);
        }
        self.refresh_locked(Some(now)).await
    }

    async fn refresh(&self, _connection_id: &str) -> anyhow::Result<String> {
        self.refresh_locked(None).await
    }

    async fn mark_needs_reauth(&self, _connection_id: &str, reason: &str) {
        self.host
            .mark_needs_reauth(&self.connection_id, self.generation, reason)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::discovery::{AuthorizationServerMetadata, TokenEndpointAuth};
    use crate::oauth::grant::host::NoDurableState;
    use crate::oauth::grant::registry::next_generation;
    use crate::oauth::http_seam::FakeHttp;
    use crate::oauth::tokens::{EXPIRY_SKEW_SECS, MemoryTokenStore};

    fn md() -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: "https://auth.example.com".into(),
            authorization_endpoint: "https://auth.example.com/authorize".into(),
            token_endpoint: "https://auth.example.com/token".into(),
            registration_endpoint: None,
            scopes_supported: vec![],
            code_challenge_methods_supported: vec!["S256".into()],
            token_endpoint_auth_methods_supported: TokenEndpointAuth::Listed(vec!["none".into()]),
            grant_types_supported: vec![],
            revocation_endpoint: None,
        }
    }

    fn broker(store: Arc<dyn TokenStore>, http: Arc<dyn OAuthHttp>) -> RefreshBroker {
        RefreshBroker::new(RefreshBrokerConfig {
            host: Arc::new(NoDurableState),
            connection_id: "t1".into(),
            store,
            http,
            metadata: md(),
            client_id: "cid".into(),
            client_secret: None,
            resource: Some("https://mcp.example.com/mcp".into()),
            scopes: vec![],
            generation: next_generation(),
            commit_lock: None,
        })
    }

    #[tokio::test]
    async fn a_live_token_is_returned_without_touching_the_network() {
        let store = Arc::new(MemoryTokenStore::with(
            "t1",
            TokenSet {
                access_token: "live".into(),
                refresh_token: Some("rt".into()),
                expires_at: Some(now_unix() + 3600),
                scopes: vec![],
            },
        ));
        let http = Arc::new(FakeHttp::default());
        let b = broker(store, http.clone());
        assert_eq!(b.access_token("t1").await.unwrap(), "live");
        assert!(http.recorded_forms.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_token_inside_the_skew_window_is_refreshed_before_use() {
        let store = Arc::new(MemoryTokenStore::with(
            "t1",
            TokenSet {
                access_token: "stale".into(),
                refresh_token: Some("rt".into()),
                expires_at: Some(now_unix() + EXPIRY_SKEW_SECS - 1),
                scopes: vec![],
            },
        ));
        let http = Arc::new(FakeHttp::default().with_post(
            "https://auth.example.com/token",
            FakeHttp::json(
                200,
                serde_json::json!({"access_token": "fresh", "expires_in": 3600}),
            ),
        ));
        let b = broker(store.clone(), http);
        assert_eq!(b.access_token("t1").await.unwrap(), "fresh");
        // Persisted, so the next process or consumer sees the new token.
        assert_eq!(store.load("t1").unwrap().unwrap().access_token, "fresh");
    }

    #[tokio::test]
    async fn an_expired_token_with_no_refresh_token_says_so_plainly() {
        let store = Arc::new(MemoryTokenStore::with(
            "t1",
            TokenSet {
                access_token: "stale".into(),
                refresh_token: None,
                expires_at: Some(now_unix() - 10),
                scopes: vec![],
            },
        ));
        let err = broker(store, Arc::new(FakeHttp::default()))
            .access_token("t1")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("authorized again"), "{err}");
    }

    #[tokio::test]
    async fn a_connection_with_no_stored_authorization_is_an_error_not_an_empty_token() {
        let err = broker(
            Arc::new(MemoryTokenStore::default()),
            Arc::new(FakeHttp::default()),
        )
        .access_token("t1")
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("no stored authorization"), "{err}");
    }

    /// Concurrent callers that all find the token expired must not each spend
    /// the refresh token: a server that rotates would invalidate all but one.
    ///
    /// This drives `access_token` — the expiry path, where the re-read inside
    /// the lock lets the losers adopt the winner's token and skip the network
    /// entirely. A forced `refresh` (the 401-recovery path) deliberately always
    /// posts, so concurrent forced refreshes are serialised rather than
    /// coalesced; that is a different guarantee and this test does not make it.
    #[tokio::test]
    async fn concurrent_refreshes_are_single_flight() {
        let store = Arc::new(MemoryTokenStore::with(
            "t1",
            TokenSet {
                access_token: "stale".into(),
                refresh_token: Some("rt".into()),
                expires_at: Some(now_unix() - 10),
                scopes: vec![],
            },
        ));
        let http = Arc::new(FakeHttp::default().with_post(
            "https://auth.example.com/token",
            FakeHttp::json(
                200,
                serde_json::json!({"access_token": "fresh", "expires_in": 3600}),
            ),
        ));
        let b = Arc::new(broker(store, http.clone()));
        let calls: Vec<_> = (0..8)
            .map(|_| {
                let b = b.clone();
                tokio::spawn(async move { b.access_token("t1").await.unwrap() })
            })
            .collect();
        for c in calls {
            assert_eq!(c.await.unwrap(), "fresh");
        }
        assert_eq!(
            http.recorded_forms.lock().unwrap().len(),
            1,
            "the expiry re-check inside the lock must collapse the herd into one refresh"
        );
    }

    /// A forced refresh (the 401 path) always calls the server, even when the
    /// stored token still looks live — the token was rejected, so "looks live"
    /// is exactly the wrong signal to trust.
    #[tokio::test]
    async fn a_forced_refresh_ignores_a_token_that_merely_looks_live() {
        let store = Arc::new(MemoryTokenStore::with(
            "t1",
            TokenSet {
                access_token: "revoked".into(),
                refresh_token: Some("rt".into()),
                expires_at: Some(now_unix() + 3600),
                scopes: vec![],
            },
        ));
        let http = Arc::new(FakeHttp::default().with_post(
            "https://auth.example.com/token",
            FakeHttp::json(200, serde_json::json!({"access_token": "fresh"})),
        ));
        let b = broker(store, http.clone());
        assert_eq!(b.refresh("t1").await.unwrap(), "fresh");
        assert_eq!(http.recorded_forms.lock().unwrap().len(), 1);
    }

    /// A refresh must not put back a grant the user removed mid-flight.
    ///
    /// The single-flight lock serialises refreshes against each other, but a
    /// disconnect does not take it. Saving unconditionally resurrected the
    /// grant, and nothing surfaced it — the store simply had a credential again.
    #[tokio::test]
    async fn a_refresh_does_not_resurrect_a_grant_removed_while_it_was_in_flight() {
        let store = Arc::new(MemoryTokenStore::with(
            "t1",
            TokenSet {
                access_token: "stale".into(),
                refresh_token: Some("rt".into()),
                expires_at: Some(now_unix() - 10),
                scopes: vec![],
            },
        ));
        // The fake yields inside `post_form`, so this clear lands while the
        // refresh is on the "network" — the real schedule, not a contrived one.
        let removing = store.clone();
        let http = Arc::new(
            FakeHttp::default()
                .with_post(
                    "https://auth.example.com/token",
                    FakeHttp::json(
                        200,
                        serde_json::json!({"access_token": "fresh", "expires_in": 3600}),
                    ),
                )
                .on_post(move || {
                    removing.clear("t1").unwrap();
                }),
        );

        let b = broker(store.clone(), http);
        let err = b.refresh("t1").await.unwrap_err().to_string();

        assert!(err.contains("was removed"), "{err}");
        assert!(
            store.load("t1").unwrap().is_none(),
            "the removed grant stayed removed"
        );
    }

    /// The host seam is what carries a failure somewhere durable. A broker with
    /// no durable host must still complete the call rather than panic or block.
    #[tokio::test]
    async fn marking_reauth_through_a_hostless_broker_is_a_no_op() {
        let b = broker(
            Arc::new(MemoryTokenStore::default()),
            Arc::new(FakeHttp::default()),
        );
        b.mark_needs_reauth("t1", "revoked at the provider").await;
    }
}

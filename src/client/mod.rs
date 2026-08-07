mod config;
mod discovery;
mod lock;
pub mod oidc;
pub mod session;
pub mod ssh;
mod store;
pub mod tofu;
mod token;

pub use config::ServiceConfig;
pub use discovery::{discover, discover_unpinned, discover_with_store};
pub use ssh::{SshAgentAuth, SshKeyInfo};
#[cfg(feature = "keyring")]
pub use store::KeyringStore;
pub use store::{StoredToken, TokenStorage, TokenStore};
pub use tofu::{TofuResult, TofuStore};
pub use token::StaticTokenAuth;

use anyhow::{Context, Result};
use tracing::info;

/// Token provider -- either OIDC, static token, or SSH key.
pub enum TokenProvider {
    Oidc(ServiceConfig),
    Static(StaticTokenAuth),
    Ssh(SshAgentAuth),
}

/// Main authentication client.
///
/// Handles token lifecycle: load cached -> refresh if expired -> browser login if needed.
pub struct AuthClient {
    provider: TokenProvider,
    store: Box<dyn TokenStorage>,
}

impl AuthClient {
    /// Create a new auth client with OIDC provider (default file-based token store).
    pub fn new(config: ServiceConfig) -> Result<Self> {
        Ok(Self {
            provider: TokenProvider::Oidc(config),
            store: Box::new(TokenStore::new()?),
        })
    }

    /// Create an OIDC auth client with a caller-supplied storage backend —
    /// e.g. [`KeyringStore`] (with the `keyring` feature) or any custom
    /// [`TokenStorage`] implementation.
    pub fn with_storage(config: ServiceConfig, storage: Box<dyn TokenStorage>) -> Self {
        Self {
            provider: TokenProvider::Oidc(config),
            store: storage,
        }
    }

    /// Create an OIDC auth client that persists tokens in the OS keychain
    /// (macOS Keychain / Windows Credential Manager).
    #[cfg(feature = "keyring")]
    pub fn new_with_keyring(config: ServiceConfig) -> Self {
        Self {
            provider: TokenProvider::Oidc(config),
            store: Box::new(KeyringStore::new()),
        }
    }

    /// Create a new auth client with a static token.
    pub fn with_static_token(token: String) -> Result<Self> {
        Ok(Self {
            provider: TokenProvider::Static(StaticTokenAuth::new(token)),
            store: Box::new(TokenStore::new()?),
        })
    }

    /// Create a new auth client that signs requests with an SSH key.
    ///
    /// If `fingerprint` is `Some`, the loaded key must match that fingerprint.
    /// If `None`, `~/.ssh/id_ed25519` is used without fingerprint validation.
    pub fn with_ssh(fingerprint: Option<String>) -> Result<Self> {
        Ok(Self {
            provider: TokenProvider::Ssh(SshAgentAuth::new(fingerprint)),
            store: Box::new(TokenStore::new()?),
        })
    }

    /// Get a valid token. Loads from cache, refreshes if expired, or initiates login.
    pub async fn token(&self) -> Result<String> {
        match &self.provider {
            TokenProvider::Static(auth) => Ok(auth.token().to_string()),
            TokenProvider::Oidc(config) => self.oidc_token(config).await,
            TokenProvider::Ssh(_) => {
                anyhow::bail!("SSH provider does not issue bearer tokens — use authorize() instead")
            }
        }
    }

    /// Produce an HTTP `Authorization` header value for a request.
    ///
    /// - OIDC / Static → `"Bearer <token>"`
    /// - SSH           → `"SSH-Signature fingerprint=…,timestamp=…,nonce=…,signature=…"`
    pub async fn authorize(
        &self,
        namespace: &str,
        method: &str,
        path_with_query: &str,
        body: &[u8],
    ) -> Result<String> {
        match &self.provider {
            TokenProvider::Static(auth) => Ok(format!("Bearer {}", auth.token())),
            TokenProvider::Oidc(config) => {
                let token = self.oidc_token(config).await?;
                Ok(format!("Bearer {token}"))
            }
            TokenProvider::Ssh(ssh) => ssh.authorize(namespace, method, path_with_query, body),
        }
    }

    /// Perform interactive login (always opens browser).
    #[cfg(feature = "browser-login")]
    pub async fn login(&self) -> Result<StoredToken> {
        match &self.provider {
            TokenProvider::Static(_) => anyhow::bail!("Cannot login with static token"),
            TokenProvider::Ssh(_) => anyhow::bail!("Cannot login with SSH provider"),
            TokenProvider::Oidc(config) => {
                let token = oidc::browser_login(
                    &config.issuer,
                    &config.client_id,
                    config.audience.as_deref(),
                    &config.redirect_uri,
                )
                .await?;
                self.store.save(&token)?;
                info!("Login successful, token stored");
                Ok(token)
            }
        }
    }

    /// Begin an RFC 8628 device-authorization flow. Returns a handle the
    /// caller uses to (a) display the verification URL + user code, and
    /// (b) `poll().await` for the user to authorize.
    ///
    /// Use this for headless principals that have no browser -- Kubernetes
    /// operators, CI workers, server-side jobs that need to act on behalf
    /// of a human.
    pub async fn begin_device_login(&self, scope: &str) -> Result<oidc::DeviceFlowHandle> {
        match &self.provider {
            TokenProvider::Oidc(config) => {
                oidc::begin_device_flow(
                    &config.issuer,
                    &config.client_id,
                    config.audience.as_deref(),
                    scope,
                )
                .await
            }
            TokenProvider::Static(_) | TokenProvider::Ssh(_) => {
                anyhow::bail!("Device login requires an OIDC provider")
            }
        }
    }

    /// Drive [`Self::begin_device_login`] to completion: invokes the supplied
    /// closure with the verification prompt (so the caller can print or
    /// otherwise display it), then polls the IdP until the user authorizes.
    /// The resulting token is persisted to disk on success.
    pub async fn device_login<F>(&self, scope: &str, show_prompt: F) -> Result<StoredToken>
    where
        F: FnOnce(&oidc::DeviceFlowPrompt),
    {
        let handle = self.begin_device_login(scope).await?;
        show_prompt(&handle.prompt);
        let token = handle.poll().await?;
        self.store.save(&token)?;
        info!("Device login successful, token stored");
        Ok(token)
    }

    /// Remove stored tokens. Synchronous and local-only -- if you want the
    /// token revoked at the IdP too (closing the leaked-laptop window), call
    /// [`Self::logout_async`] instead.
    pub fn logout(&self) -> Result<()> {
        match &self.provider {
            TokenProvider::Static(_) | TokenProvider::Ssh(_) => Ok(()),
            TokenProvider::Oidc(config) => {
                self.store.remove(&config.issuer)?;
                info!("Logged out (local only), token removed from disk");
                Ok(())
            }
        }
    }

    /// Log out: remove the local token AND revoke it at the IdP via RFC 7009.
    ///
    /// Best-effort revocation -- a network failure does not prevent the
    /// local removal, but is logged. If the IdP doesn't advertise a
    /// `revocation_endpoint`, the local removal still happens and a warning
    /// is logged.
    pub async fn logout_async(&self) -> Result<()> {
        match &self.provider {
            TokenProvider::Static(_) | TokenProvider::Ssh(_) => Ok(()),
            TokenProvider::Oidc(config) => {
                // Load the current tokens so we can revoke them. Best-effort:
                // if loading fails, we still proceed with the local cleanup.
                if let Ok(Some(stored)) = self.store.load(&config.issuer) {
                    // Revoke the refresh token first -- per RFC 7009 §2.2 this
                    // also revokes any access tokens it spawned at well-behaved
                    // IdPs, so it's the right one to lead with.
                    if let Some(refresh) = stored.refresh_token.as_deref()
                        && let Err(e) = oidc::revoke(
                            &config.issuer,
                            &config.client_id,
                            refresh,
                            oidc::TokenKind::Refresh,
                        )
                        .await
                    {
                        info!(error = %e, "refresh-token revocation failed (continuing)");
                    }
                    // Some IdPs treat the ID token as the access token; revoke
                    // it too (separate call so a 4xx on the previous one
                    // doesn't block this).
                    if let Err(e) = oidc::revoke(
                        &config.issuer,
                        &config.client_id,
                        &stored.id_token,
                        oidc::TokenKind::Access,
                    )
                    .await
                    {
                        info!(error = %e, "id-token revocation failed (continuing)");
                    }
                }
                self.store.remove(&config.issuer)?;
                info!("Logged out, token revoked + removed");
                Ok(())
            }
        }
    }

    /// Ask the IdP whether the locally-cached access token is still valid
    /// (RFC 7662 token introspection).
    ///
    /// Useful for "is this token revoked right now" checks that bypass any
    /// validation cache, or for opaque tokens that can't be locally checked.
    pub async fn introspect(&self) -> Result<oidc::IntrospectionResult> {
        match &self.provider {
            TokenProvider::Oidc(config) => {
                let stored = self
                    .store
                    .load(&config.issuer)?
                    .context("no stored token to introspect")?;
                oidc::introspect(
                    &config.issuer,
                    &config.client_id,
                    &stored.id_token,
                    oidc::TokenKind::Access,
                )
                .await
            }
            TokenProvider::Static(_) | TokenProvider::Ssh(_) => {
                anyhow::bail!("Introspection requires an OIDC provider")
            }
        }
    }

    async fn oidc_token(&self, config: &ServiceConfig) -> Result<String> {
        // Fast path: a valid cached token needs no cross-process coordination.
        if let Some(stored) = self.store.load(&config.issuer)?
            && !stored.is_expired()
        {
            return Ok(stored.id_token);
        }

        // Serialise the refresh/login across processes: rotating refresh
        // tokens are single-use at many IdPs, so two concurrent CLIs racing
        // the same token trip reuse detection and revoke the grant family.
        // Waiting here usually means another process is refreshing (or in a
        // browser login) for this issuer — when it finishes, the re-check
        // below picks up its fresh token.
        let _refresh_lock = lock::RefreshLock::acquire(&config.issuer).await?;

        // Re-check under the lock.
        if let Some(stored) = self.store.load(&config.issuer)? {
            if !stored.is_expired() {
                return Ok(stored.id_token);
            }
            info!("Token expired, attempting refresh");

            // If we have a refresh token, exchange it for a fresh ID token.
            if let Some(refresh) = stored.refresh_token.as_deref() {
                match oidc::refresh(
                    &config.issuer,
                    &config.client_id,
                    &config.redirect_uri,
                    refresh,
                )
                .await
                {
                    Ok(mut refreshed) => {
                        // Carry application metadata forward across the refresh.
                        refreshed.extra = stored.extra.clone();
                        self.store.save(&refreshed)?;
                        return Ok(refreshed.id_token);
                    }
                    Err(e) => {
                        info!(error = %e, "Refresh failed, falling back to interactive login");
                    }
                }
            } else {
                info!("No refresh token available, interactive login required");
            }
        }

        // No valid cached token / refresh failed -- interactive login.
        #[cfg(feature = "browser-login")]
        {
            let token = self.login().await?;
            Ok(token.id_token)
        }
        #[cfg(not(feature = "browser-login"))]
        {
            anyhow::bail!(
                "no valid cached token and refresh unavailable; enable the \
                 `browser-login` feature for interactive login"
            )
        }
    }
}

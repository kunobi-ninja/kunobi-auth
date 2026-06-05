use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Stored token data.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredToken {
    /// The ID token (JWT).
    pub id_token: String,
    /// Refresh token for obtaining new ID tokens.
    pub refresh_token: Option<String>,
    /// When the ID token expires (Unix timestamp).
    pub expires_at: Option<i64>,
    /// Issuer this token was obtained from.
    pub issuer: String,
    /// Application-defined metadata persisted alongside the token — e.g. a
    /// cached user profile, decoded display claims, or any session state a
    /// consumer needs to keep next to the credential. kunobi-auth never reads
    /// this; it is opaque pass-through. Empty by default (and omitted from the
    /// serialized form when empty, so older token files load unchanged).
    /// [`AuthClient`](crate::client::AuthClient) preserves it across refreshes.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl fmt::Debug for StoredToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredToken")
            .field("id_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("issuer", &self.issuer)
            // Show only the metadata keys — values may be sensitive.
            .field("extra_keys", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl StoredToken {
    /// Construct a token with no application metadata.
    pub fn new(
        id_token: String,
        refresh_token: Option<String>,
        expires_at: Option<i64>,
        issuer: String,
    ) -> Self {
        Self {
            id_token,
            refresh_token,
            expires_at,
            issuer,
            extra: serde_json::Map::new(),
        }
    }

    /// Attach application metadata (builder style).
    pub fn with_extra(mut self, extra: serde_json::Map<String, serde_json::Value>) -> Self {
        self.extra = extra;
        self
    }

    /// Check if the token is expired (with 60s buffer).
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            // saturating_sub: a crafted `exp` near i64::MIN must not wrap.
            Some(exp) => chrono::Utc::now().timestamp() > exp.saturating_sub(60),
            None => true,
        }
    }
}

/// Manages token persistence in ~/.config/kunobi/tokens/
pub struct TokenStore {
    dir: PathBuf,
}

impl TokenStore {
    pub fn new() -> Result<Self> {
        let dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
            .join("kunobi")
            .join("tokens");
        std::fs::create_dir_all(&dir)?;
        set_dir_mode_0700(&dir)?;
        Ok(Self { dir })
    }

    /// Load a stored token for the given issuer.
    pub fn load(&self, issuer: &str) -> Result<Option<StoredToken>> {
        let path = self.token_path(issuer);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)?;
        let token: StoredToken = serde_json::from_str(&data)?;
        Ok(Some(token))
    }

    /// Store a token for the given issuer using an atomic temp-file rename
    /// so a partial write can never be observed.
    pub fn save(&self, token: &StoredToken) -> Result<()> {
        let path = self.token_path(&token.issuer);
        let data = serde_json::to_string_pretty(token)?;

        let mut tmp = tempfile::NamedTempFile::new_in(&self.dir)?;
        use std::io::Write as _;
        tmp.write_all(data.as_bytes())?;
        tmp.as_file().sync_all()?;
        set_file_mode_0600(tmp.path())?;
        tmp.persist(&path)
            .map_err(|e| anyhow::anyhow!("Failed to persist token file: {}", e.error))?;
        Ok(())
    }

    /// Remove stored token for the given issuer.
    pub fn remove(&self, issuer: &str) -> Result<()> {
        let path = self.token_path(issuer);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn token_path(&self, issuer: &str) -> PathBuf {
        // Hash the issuer URL to a safe, collision-resistant filename. SHA-256
        // is used (rather than `DefaultHasher`) because its output is stable
        // across Rust toolchain versions -- `DefaultHasher`'s is not, which
        // would silently orphan stored tokens after an upgrade.
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(issuer.as_bytes());
        self.dir.join(format!("{}.json", hex::encode(digest)))
    }
}

/// Pluggable backend for persisting [`StoredToken`]s, keyed by issuer.
///
/// The default [`TokenStore`] writes JSON files under the user config dir.
/// Enable the `keyring` feature for an OS keychain-backed [`KeyringStore`].
/// [`AuthClient`](crate::client::AuthClient) holds a `Box<dyn TokenStorage>`,
/// so callers can supply their own backend via
/// [`AuthClient::with_storage`](crate::client::AuthClient::with_storage).
pub trait TokenStorage: Send + Sync {
    /// Load the stored token for `issuer`, if any.
    fn load(&self, issuer: &str) -> Result<Option<StoredToken>>;
    /// Persist `token` (keyed by its `issuer`).
    fn save(&self, token: &StoredToken) -> Result<()>;
    /// Remove any stored token for `issuer`. Removing a missing entry is Ok.
    fn remove(&self, issuer: &str) -> Result<()>;
}

impl TokenStorage for TokenStore {
    fn load(&self, issuer: &str) -> Result<Option<StoredToken>> {
        TokenStore::load(self, issuer)
    }
    fn save(&self, token: &StoredToken) -> Result<()> {
        TokenStore::save(self, token)
    }
    fn remove(&self, issuer: &str) -> Result<()> {
        TokenStore::remove(self, issuer)
    }
}

/// OS keychain-backed token storage (macOS Keychain / Windows Credential
/// Manager via the `keyring` crate). One keychain entry per issuer holds the
/// serialized [`StoredToken`].
///
/// # Platform support
/// - **macOS / Windows**: native backends (`apple-native` / `windows-native`).
/// - **Windows caveat**: Credential Manager caps a credential blob at 2560
///   bytes; [`save`](TokenStorage::save) returns an explicit error rather than
///   silently truncating if a large token (e.g. many `extra` claims) exceeds it.
/// - **Linux / others**: NO native backend is compiled in by default, so the
///   `keyring` crate falls back to an in-memory store that does **not** persist
///   across restarts. Enable the crate's `sync-secret-service` (or
///   `linux-native`) backend before relying on `KeyringStore` on Linux, or use
///   the file-based [`TokenStore`] there.
#[cfg(feature = "keyring")]
pub struct KeyringStore {
    service: String,
}

#[cfg(feature = "keyring")]
impl KeyringStore {
    /// Create a store using the default keychain service name `kunobi-auth`.
    pub fn new() -> Self {
        Self::with_service("kunobi-auth")
    }

    /// Create a store under a custom keychain service name — useful to isolate
    /// build variants or test runs that would otherwise share entries.
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, issuer: &str) -> Result<keyring::Entry> {
        // Hash the issuer to a stable, keychain-safe account key (mirrors the
        // file backend's filename hashing).
        use sha2::{Digest, Sha256};
        let account = hex::encode(Sha256::digest(issuer.as_bytes()));
        keyring::Entry::new(&self.service, &account)
            .map_err(|e| anyhow::anyhow!("Failed to open keychain entry: {e}"))
    }
}

#[cfg(feature = "keyring")]
impl Default for KeyringStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "keyring")]
impl TokenStorage for KeyringStore {
    fn load(&self, issuer: &str) -> Result<Option<StoredToken>> {
        match self.entry(issuer)?.get_password() {
            Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("keychain read failed: {e}")),
        }
    }

    fn save(&self, token: &StoredToken) -> Result<()> {
        let json = serde_json::to_string(token)?;
        #[cfg(target_os = "windows")]
        {
            // Windows Credential Manager caps a credential blob at 2560 bytes.
            // Fail loudly instead of letting the OS silently reject the write.
            const WINCRED_MAX_BYTES: usize = 2560;
            if json.len() > WINCRED_MAX_BYTES {
                anyhow::bail!(
                    "token for {} is {} bytes, exceeding the Windows Credential Manager \
                     {}-byte limit; reduce token/`extra` size or use a file-based TokenStore",
                    token.issuer,
                    json.len(),
                    WINCRED_MAX_BYTES
                );
            }
        }
        self.entry(&token.issuer)?
            .set_password(&json)
            .map_err(|e| anyhow::anyhow!("keychain write failed: {e}"))
    }

    fn remove(&self, issuer: &str) -> Result<()> {
        match self.entry(issuer)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("keychain delete failed: {e}")),
        }
    }
}

#[cfg(unix)]
fn set_file_mode_0600(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode_0600(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode_0700(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future_token() -> StoredToken {
        StoredToken::new(
            "eyJhbGciOiJSUzI1NiJ9.test".to_string(),
            Some("refresh-abc".to_string()),
            Some(chrono::Utc::now().timestamp() + 3600),
            "https://issuer.example.com".to_string(),
        )
    }

    fn expired_token() -> StoredToken {
        StoredToken::new(
            "eyJhbGciOiJSUzI1NiJ9.expired".to_string(),
            None,
            Some(chrono::Utc::now().timestamp() - 120),
            "https://issuer.example.com".to_string(),
        )
    }

    #[test]
    fn test_is_expired_false_for_future() {
        let token = future_token();
        assert!(!token.is_expired());
    }

    #[test]
    fn test_is_expired_true_for_past() {
        let token = expired_token();
        assert!(token.is_expired());
    }

    #[test]
    fn test_is_expired_with_60s_buffer() {
        // Token that expires in 30 seconds -- within the 60s buffer, should be "expired"
        let token = StoredToken::new(
            "jwt".to_string(),
            None,
            Some(chrono::Utc::now().timestamp() + 30),
            "https://issuer.example.com".to_string(),
        );
        assert!(token.is_expired());
    }

    #[test]
    fn test_is_expired_none_returns_true() {
        let token = StoredToken::new(
            "jwt".to_string(),
            None,
            None,
            "https://issuer.example.com".to_string(),
        );
        assert!(token.is_expired());
    }

    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_store() -> TokenStore {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join("kunobi-auth-test").join(format!(
            "{}-{}",
            std::process::id(),
            id
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TokenStore { dir }
    }

    fn cleanup_store(store: &TokenStore) {
        let _ = std::fs::remove_dir_all(&store.dir);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let store = temp_store();
        let token = future_token();
        store.save(&token).unwrap();

        let loaded = store.load(&token.issuer).unwrap().unwrap();
        assert_eq!(loaded.id_token, token.id_token);
        assert_eq!(loaded.refresh_token, token.refresh_token);
        assert_eq!(loaded.expires_at, token.expires_at);
        assert_eq!(loaded.issuer, token.issuer);

        cleanup_store(&store);
    }

    #[test]
    fn test_load_nonexistent_returns_none() {
        let store = temp_store();
        let result = store.load("https://no-such-issuer.example.com").unwrap();
        assert!(result.is_none());
        cleanup_store(&store);
    }

    #[test]
    fn test_remove_token() {
        let store = temp_store();
        let token = future_token();
        store.save(&token).unwrap();

        // Confirm it exists
        assert!(store.load(&token.issuer).unwrap().is_some());

        // Remove it
        store.remove(&token.issuer).unwrap();

        // Confirm it's gone
        assert!(store.load(&token.issuer).unwrap().is_none());

        cleanup_store(&store);
    }

    #[test]
    fn test_remove_nonexistent_does_not_error() {
        let store = temp_store();
        // Should not panic or error
        store.remove("https://nonexistent.example.com").unwrap();
        cleanup_store(&store);
    }

    #[test]
    fn test_stored_token_serialization() {
        let token = future_token();
        let json = serde_json::to_string(&token).unwrap();
        let back: StoredToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id_token, token.id_token);
        assert_eq!(back.issuer, token.issuer);
    }

    #[test]
    fn test_stored_token_debug_redacts_credentials() {
        let token = future_token();
        let debug = format!("{token:?}");
        assert!(debug.contains("StoredToken"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains(&token.issuer));
        assert!(!debug.contains(&token.id_token));
        assert!(!debug.contains(token.refresh_token.as_deref().unwrap()));
    }

    fn extra_map() -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert("display_name".into(), serde_json::json!("Jane Doe"));
        m.insert("avatar_url".into(), serde_json::json!("https://x/a.png"));
        m
    }

    #[test]
    fn test_extra_roundtrips_through_file_store() {
        let store = temp_store();
        let token = future_token().with_extra(extra_map());
        store.save(&token).unwrap();

        let loaded = store.load(&token.issuer).unwrap().unwrap();
        assert_eq!(loaded.extra, extra_map());
        assert_eq!(loaded.extra["display_name"], serde_json::json!("Jane Doe"));

        cleanup_store(&store);
    }

    #[test]
    fn test_empty_extra_omitted_and_old_files_load() {
        // Empty extra is omitted from the serialized form ...
        let token = future_token();
        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("extra"));
        // ... and a serialized token with no `extra` key deserializes fine.
        let legacy =
            r#"{"id_token":"j","refresh_token":null,"expires_at":null,"issuer":"https://i"}"#;
        let back: StoredToken = serde_json::from_str(legacy).unwrap();
        assert!(back.extra.is_empty());
    }

    #[test]
    fn test_debug_redacts_extra_values_shows_keys() {
        let token = future_token().with_extra(extra_map());
        let debug = format!("{token:?}");
        assert!(debug.contains("display_name")); // keys shown
        assert!(!debug.contains("Jane Doe")); // values not leaked
    }
}

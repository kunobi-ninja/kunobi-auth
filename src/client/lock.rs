//! Cross-process serialisation of the token refresh flow.
//!
//! Rotating refresh tokens are single-use at many IdPs: two processes racing
//! the same stored refresh token means one wins and the other presents a
//! consumed token, tripping the IdP's reuse detection and revoking the whole
//! grant family. An OS advisory file lock (`std::fs::File::lock`: flock /
//! LockFileEx) serialises the load→refresh→save sequence across processes;
//! the waiter then finds the winner's fresh token in the store instead of
//! re-refreshing.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Held for the duration of a load→refresh→save (or interactive login)
/// sequence. The OS releases the advisory lock when the file handle closes,
/// i.e. when this value drops — including on panic or process death.
pub(crate) struct RefreshLock {
    _file: std::fs::File,
}

impl RefreshLock {
    /// Acquire the per-issuer refresh lock, blocking (off the async runtime)
    /// until any concurrent holder releases it. A long wait usually means
    /// another process is mid-refresh or mid-browser-login for the same
    /// issuer; when it finishes, its fresh token is in the store for us.
    pub(crate) async fn acquire(issuer: &str) -> Result<Self> {
        let path = lock_path("refresh", issuer)?;
        tokio::task::spawn_blocking(move || {
            Ok(Self {
                _file: open_locked(&path)?,
            })
        })
        .await
        .context("refresh-lock task panicked")?
    }
}

/// Synchronous cross-process advisory lock for sync call sites (e.g. TOFU).
/// Same release-on-drop semantics as [`RefreshLock`]; blocks the calling
/// thread until the holder releases.
pub(crate) struct ProcessLock {
    _file: std::fs::File,
}

impl ProcessLock {
    pub(crate) fn acquire(scope: &str, key: &str) -> Result<Self> {
        Ok(Self {
            _file: open_locked(&lock_path(scope, key)?)?,
        })
    }
}

/// Create the parent dir, open (creating) the lock file, and block until the
/// OS advisory lock is held.
fn open_locked(path: &std::path::Path) -> Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .with_context(|| format!("Failed to open lock {}", path.display()))?;
    tracing::debug!(path = %path.display(), "acquiring lock");
    file.lock()
        .with_context(|| format!("Failed to lock {}", path.display()))?;
    Ok(file)
}

/// Per-scope/key lock file under the same config root as the token store. The
/// key is hashed for the same reason token files are: a stable, safe
/// filename for arbitrary URLs.
fn lock_path(scope: &str, key: &str) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key.as_bytes());
    Ok(dirs::config_dir()
        .context("Could not determine config directory")?
        .join("kunobi")
        .join("locks")
        .join(format!("{scope}-{}.lock", hex::encode(digest))))
}

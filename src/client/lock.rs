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
        let path = lock_path(issuer)?;
        tokio::task::spawn_blocking(move || {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create {}", parent.display()))?;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
                .with_context(|| format!("Failed to open refresh lock {}", path.display()))?;
            tracing::debug!(path = %path.display(), "acquiring refresh lock");
            file.lock()
                .with_context(|| format!("Failed to lock {}", path.display()))?;
            Ok(Self { _file: file })
        })
        .await
        .context("refresh-lock task panicked")?
    }
}

/// Per-issuer lock file under the same config root as the token store. The
/// issuer is hashed for the same reason token files are: a stable, safe
/// filename for arbitrary URLs.
fn lock_path(issuer: &str) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(issuer.as_bytes());
    Ok(dirs::config_dir()
        .context("Could not determine config directory")?
        .join("kunobi")
        .join("locks")
        .join(format!("refresh-{}.lock", hex::encode(digest))))
}

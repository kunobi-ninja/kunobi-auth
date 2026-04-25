//! Trust-on-first-use (TOFU) store for SSH service audience pinning.
//!
//! On first connection to a service the audience claim is recorded.
//! Subsequent connections verify the audience matches what was stored.
//! A mismatch signals a potential MITM and is surfaced as
//! [`TofuResult::AudienceChanged`].
//!
//! The store is process-local-locked (`std::sync::Mutex`) and writes are
//! atomic via `tempfile::persist`, so concurrent `verify`/`trust` calls
//! within a process do not race. File permissions are set to `0o600` so
//! only the owner can read or modify the trust list.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// A record stored for a single service endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownService {
    pub audience: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Result of a TOFU verification check.
#[derive(Debug)]
pub enum TofuResult {
    /// The endpoint has never been seen before.
    FirstConnect { endpoint: String, audience: String },
    /// The endpoint is known and the audience matches.
    Trusted,
    /// The endpoint is known but the audience has changed.
    AudienceChanged {
        endpoint: String,
        previous: String,
        current: String,
    },
}

/// Persistent TOFU store backed by a JSON file.
pub struct TofuStore {
    path: PathBuf,
    /// Process-local lock to serialise read-modify-write sequences.
    lock: Mutex<()>,
}

impl TofuStore {
    /// Create a store that uses the default path:
    /// `~/.config/kunobi/known_services.json`.
    ///
    /// Eagerly creates `~/.config/kunobi/` with mode `0o700` (unix only).
    pub fn new() -> Result<Self> {
        let path = dirs::home_dir()
            .context("No home directory found")?
            .join(".config/kunobi/known_services.json");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
            // Best-effort: tighten permissions on a directory we just claimed.
            let _ = set_dir_mode_0700(parent);
        }
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }

    /// Create a store backed by an arbitrary path (useful for tests).
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    /// Verify an endpoint + audience pair against the store.
    ///
    /// Does NOT automatically record the entry — call [`Self::trust`] after
    /// prompting the user.
    pub fn verify(&self, endpoint: &str, audience: &str) -> Result<TofuResult> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("TOFU store mutex poisoned"))?;
        let known = self.load_locked()?;

        match known.get(endpoint) {
            None => Ok(TofuResult::FirstConnect {
                endpoint: endpoint.to_string(),
                audience: audience.to_string(),
            }),
            Some(entry) if entry.audience == audience => Ok(TofuResult::Trusted),
            Some(entry) => Ok(TofuResult::AudienceChanged {
                endpoint: endpoint.to_string(),
                previous: entry.audience.clone(),
                current: audience.to_string(),
            }),
        }
    }

    /// Record (or update) trust for `endpoint` with `audience`.
    pub fn trust(&self, endpoint: &str, audience: &str) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("TOFU store mutex poisoned"))?;
        let mut known = self.load_locked()?;

        let now = now_rfc3339();

        known
            .entry(endpoint.to_string())
            .and_modify(|e| {
                e.audience = audience.to_string();
                e.last_seen = now.clone();
            })
            .or_insert_with(|| KnownService {
                audience: audience.to_string(),
                first_seen: now.clone(),
                last_seen: now.clone(),
            });

        self.save_locked(&known)
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn load_locked(&self) -> Result<HashMap<String, KnownService>> {
        if !self.path.exists() {
            return Ok(HashMap::new());
        }

        let data = std::fs::read_to_string(&self.path)
            .with_context(|| format!("Failed to read {}", self.path.display()))?;

        serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse {}", self.path.display()))
    }

    fn save_locked(&self, known: &HashMap<String, KnownService>) -> Result<()> {
        // Ensure parent directory exists. Mode is set in `new()`; we do not
        // re-chmod here because the parent may already be owned/managed by the
        // caller (tests pass an arbitrary path under /tmp) and tightening
        // perms on a system-shared directory will fail or surprise the user.
        let parent = self
            .path
            .parent()
            .context("TOFU store path must have a parent directory")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;

        let json =
            serde_json::to_string_pretty(known).context("Failed to serialise known services")?;

        // Atomic write: write to a temp file in the same directory, fsync, then
        // rename over the destination so a concurrent reader never observes a
        // half-written file.
        let mut tmp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("Failed to create temp file in {}", parent.display()))?;
        use std::io::Write as _;
        tmp.write_all(json.as_bytes())
            .context("Failed to write TOFU store")?;
        tmp.as_file()
            .sync_all()
            .context("Failed to fsync TOFU store")?;

        set_file_mode_0600(tmp.path())?;
        tmp.persist(&self.path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to persist TOFU store {}: {}",
                self.path.display(),
                e.error
            )
        })?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_file_mode_0600(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to chmod 0600 {}", path.display()))
}

#[cfg(not(unix))]
fn set_file_mode_0600(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode_0700(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("Failed to chmod 0700 {}", path.display()))
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn temp_store() -> TofuStore {
        // Create a temp file path (we delete it so the store starts empty).
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_path_buf();
        drop(f); // delete the file -- store should handle missing file gracefully
        TofuStore::with_path(path)
    }

    #[test]
    fn test_first_connect() {
        let store = temp_store();
        let result = store
            .verify("https://api.example.com", "api://example")
            .unwrap();
        assert!(
            matches!(result, TofuResult::FirstConnect { .. }),
            "expected FirstConnect, got {result:?}"
        );
    }

    #[test]
    fn test_trusted_after_trust() {
        let store = temp_store();
        store
            .trust("https://api.example.com", "api://example")
            .unwrap();

        let result = store
            .verify("https://api.example.com", "api://example")
            .unwrap();
        assert!(
            matches!(result, TofuResult::Trusted),
            "expected Trusted after trust(), got {result:?}"
        );
    }

    #[test]
    fn test_audience_changed() {
        let store = temp_store();
        store
            .trust("https://api.example.com", "api://old-audience")
            .unwrap();

        let result = store
            .verify("https://api.example.com", "api://new-audience")
            .unwrap();

        match result {
            TofuResult::AudienceChanged {
                previous, current, ..
            } => {
                assert_eq!(previous, "api://old-audience");
                assert_eq!(current, "api://new-audience");
            }
            other => panic!("expected AudienceChanged, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let store = temp_store();
        store.trust("https://api.example.com", "aud").unwrap();
        let mode = std::fs::metadata(&store.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
    }
}

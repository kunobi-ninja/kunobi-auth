//! Trust-on-first-use (TOFU) store for pinning a service's issuer + audience.
//!
//! On first connection to a service its issuer and audience are recorded.
//! Subsequent connections check that what's presented still matches what was
//! stored. A mismatch signals a potential MITM. Three gates, by strictness:
//!
//! - [`TofuStore::check_and_pin`] — automatic TOFU: pins unknown endpoints,
//!   errors on any change. This is what [`crate::client::discover`] applies
//!   by default.
//! - [`TofuStore::verify`] — reports a status ([`TofuResult::IssuerChanged`] /
//!   [`TofuResult::AudienceChanged`] / …) you can act on, e.g. to prompt the
//!   user before calling [`TofuStore::trust`].
//! - [`TofuStore::verify_or_reject`] — strict, **fail-closed**: `Err` on any
//!   mismatch *or* on an unpinned service, so a caller cannot silently trust
//!   a new or changed endpoint.
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
///
/// `#[non_exhaustive]`: the documented construction path is
/// [`TofuStore::trust`], so fields may be added (e.g. `issuer`) without a
/// breaking change for downstream consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KnownService {
    /// The pinned OIDC issuer. `#[serde(default)]` so trust files written
    /// before issuer pinning (audience-only) still deserialize; such legacy
    /// entries have an empty issuer and are rejected by
    /// [`TofuStore::verify_or_reject`] until re-trusted.
    #[serde(default)]
    pub issuer: String,
    pub audience: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Result of a TOFU verification check.
#[derive(Debug)]
#[non_exhaustive]
pub enum TofuResult {
    /// The endpoint has never been seen before.
    FirstConnect { endpoint: String, audience: String },
    /// The endpoint is known and both issuer and audience match.
    Trusted,
    /// The endpoint is known but the audience has changed.
    AudienceChanged {
        endpoint: String,
        previous: String,
        current: String,
    },
    /// The endpoint is known but the issuer has changed (possible MITM
    /// steering the client onto an attacker-controlled IdP).
    IssuerChanged {
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

    /// Verify an endpoint + issuer + audience triple against the store.
    ///
    /// Does NOT automatically record the entry — call [`Self::trust`] after
    /// prompting the user. An issuer change is reported before an audience
    /// change (it is the stronger MITM signal). A legacy entry pinned before
    /// issuer support (empty stored issuer) skips the issuer comparison; call
    /// [`Self::trust`] to upgrade such a pin.
    pub fn verify(&self, endpoint: &str, issuer: &str, audience: &str) -> Result<TofuResult> {
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
            Some(entry) if !entry.issuer.is_empty() && entry.issuer != issuer => {
                Ok(TofuResult::IssuerChanged {
                    endpoint: endpoint.to_string(),
                    previous: entry.issuer.clone(),
                    current: issuer.to_string(),
                })
            }
            Some(entry) if entry.audience == audience => Ok(TofuResult::Trusted),
            Some(entry) => Ok(TofuResult::AudienceChanged {
                endpoint: endpoint.to_string(),
                previous: entry.audience.clone(),
                current: audience.to_string(),
            }),
        }
    }

    /// Fail-closed *automatic* TOFU gate: pin on first contact, verify
    /// afterwards, reject on any change.
    ///
    /// - Unknown endpoint → pinned now, returns [`TofuResult::FirstConnect`].
    /// - Known endpoint, issuer + audience match → returns
    ///   [`TofuResult::Trusted`] (and refreshes `last_seen`).
    /// - Legacy entry pinned without an issuer → upgraded in place when the
    ///   audience still matches (mirrors [`Self::trust`]'s upgrade path).
    /// - Issuer or audience mismatch → `Err` (possible MITM); resolving it
    ///   requires an explicit [`Self::trust`] call, e.g. after prompting.
    ///
    /// This is what the crate's own discovery flow uses; use
    /// [`Self::verify`] + [`Self::trust`] instead when you want to prompt the
    /// user before pinning.
    pub fn check_and_pin(
        &self,
        endpoint: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<TofuResult> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("TOFU store mutex poisoned"))?;
        let mut known = self.load_locked()?;
        let now = now_rfc3339();

        let Some(entry) = known.get_mut(endpoint) else {
            known.insert(
                endpoint.to_string(),
                KnownService {
                    issuer: issuer.to_string(),
                    audience: audience.to_string(),
                    first_seen: now.clone(),
                    last_seen: now,
                },
            );
            self.save_locked(&known)?;
            return Ok(TofuResult::FirstConnect {
                endpoint: endpoint.to_string(),
                audience: audience.to_string(),
            });
        };

        if !entry.issuer.is_empty() && entry.issuer != issuer {
            anyhow::bail!(
                "TOFU: issuer changed for {endpoint} (possible MITM): pinned {pinned:?}, presented {issuer:?}. \
                 If this change is expected, re-establish trust explicitly with trust()",
                pinned = entry.issuer
            );
        }
        if entry.audience != audience {
            anyhow::bail!(
                "TOFU: audience changed for {endpoint} (possible MITM): pinned {pinned:?}, presented {audience:?}. \
                 If this change is expected, re-establish trust explicitly with trust()",
                pinned = entry.audience
            );
        }

        // Match (or legacy issuer upgrade): refresh the pin's metadata.
        entry.issuer = issuer.to_string();
        entry.last_seen = now;
        self.save_locked(&known)?;
        Ok(TofuResult::Trusted)
    }

    /// Fail-closed trust gate: returns `Ok(())` **only** when `endpoint` is
    /// already pinned *and* the pinned issuer and audience both match exactly.
    ///
    /// Unlike [`Self::verify`] (which reports a status and returns `Ok` even on
    /// a mismatch), this rejects:
    /// - an unpinned endpoint (first contact) — establish trust explicitly with
    ///   [`Self::trust`] first, e.g. after prompting the user;
    /// - a legacy entry pinned before issuer support (empty issuer) — re-trust
    ///   to upgrade the pin;
    /// - any change of issuer or audience (possible MITM).
    ///
    /// A caller that routes through `verify_or_reject` therefore cannot be
    /// silently steered onto a new or substituted issuer.
    pub fn verify_or_reject(&self, endpoint: &str, issuer: &str, audience: &str) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("TOFU store mutex poisoned"))?;
        let known = self.load_locked()?;

        let Some(entry) = known.get(endpoint) else {
            anyhow::bail!(
                "TOFU: refusing to trust unpinned service {endpoint}; call trust() to establish first-use trust"
            );
        };
        if entry.issuer.is_empty() {
            anyhow::bail!(
                "TOFU: service {endpoint} was pinned without an issuer (legacy entry); re-run trust() to upgrade the pin"
            );
        }
        if entry.issuer != issuer {
            anyhow::bail!(
                "TOFU: issuer changed for {endpoint} (possible MITM): pinned {pinned:?}, presented {issuer:?}",
                pinned = entry.issuer
            );
        }
        if entry.audience != audience {
            anyhow::bail!(
                "TOFU: audience changed for {endpoint} (possible MITM): pinned {pinned:?}, presented {audience:?}",
                pinned = entry.audience
            );
        }
        Ok(())
    }

    /// Record (or update) trust for `endpoint`, pinning its `issuer` and
    /// `audience`. Overwrites any previous pin for the endpoint (this is how a
    /// legacy or rotated entry is upgraded).
    pub fn trust(&self, endpoint: &str, issuer: &str, audience: &str) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("TOFU store mutex poisoned"))?;
        let mut known = self.load_locked()?;

        let now = now_rfc3339();

        known
            .entry(endpoint.to_string())
            .and_modify(|e| {
                e.issuer = issuer.to_string();
                e.audience = audience.to_string();
                e.last_seen = now.clone();
            })
            .or_insert_with(|| KnownService {
                issuer: issuer.to_string(),
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
            .verify("https://api.example.com", "https://idp", "api://example")
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
            .trust("https://api.example.com", "https://idp", "api://example")
            .unwrap();

        let result = store
            .verify("https://api.example.com", "https://idp", "api://example")
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
            .trust(
                "https://api.example.com",
                "https://idp",
                "api://old-audience",
            )
            .unwrap();

        let result = store
            .verify(
                "https://api.example.com",
                "https://idp",
                "api://new-audience",
            )
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

    #[test]
    fn test_issuer_changed_reported_before_audience() {
        let store = temp_store();
        store
            .trust("https://api.example.com", "https://idp", "aud")
            .unwrap();

        // Both issuer and audience differ: the issuer change must win.
        let result = store
            .verify("https://api.example.com", "https://evil-idp", "other-aud")
            .unwrap();
        match result {
            TofuResult::IssuerChanged {
                previous, current, ..
            } => {
                assert_eq!(previous, "https://idp");
                assert_eq!(current, "https://evil-idp");
            }
            other => panic!("expected IssuerChanged, got {other:?}"),
        }
    }

    // ── check_and_pin: automatic fail-closed TOFU ─────────────────────────

    #[test]
    fn check_and_pin_pins_on_first_contact_then_trusts() {
        let store = temp_store();
        let first = store
            .check_and_pin("https://api.example.com", "https://idp", "aud")
            .unwrap();
        assert!(matches!(first, TofuResult::FirstConnect { .. }));

        let second = store
            .check_and_pin("https://api.example.com", "https://idp", "aud")
            .unwrap();
        assert!(matches!(second, TofuResult::Trusted));
    }

    #[test]
    fn check_and_pin_rejects_issuer_change() {
        let store = temp_store();
        store
            .check_and_pin("https://api.example.com", "https://idp", "aud")
            .unwrap();
        let err = store
            .check_and_pin("https://api.example.com", "https://evil-idp", "aud")
            .unwrap_err();
        assert!(err.to_string().contains("issuer changed"), "{err}");
    }

    #[test]
    fn check_and_pin_rejects_audience_change() {
        let store = temp_store();
        store
            .check_and_pin("https://api.example.com", "https://idp", "aud")
            .unwrap();
        let err = store
            .check_and_pin("https://api.example.com", "https://idp", "other")
            .unwrap_err();
        assert!(err.to_string().contains("audience changed"), "{err}");
    }

    #[test]
    fn check_and_pin_upgrades_legacy_entry_without_issuer() {
        let store = temp_store();
        // Simulate a pre-issuer pin: trust with an empty issuer.
        store.trust("https://api.example.com", "", "aud").unwrap();

        // Same audience: the pin upgrades in place with the presented issuer…
        let result = store
            .check_and_pin("https://api.example.com", "https://idp", "aud")
            .unwrap();
        assert!(matches!(result, TofuResult::Trusted));

        // …and from then on the issuer is enforced.
        let err = store
            .check_and_pin("https://api.example.com", "https://other-idp", "aud")
            .unwrap_err();
        assert!(err.to_string().contains("issuer changed"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let store = temp_store();
        store
            .trust("https://api.example.com", "https://idp", "aud")
            .unwrap();
        let mode = std::fs::metadata(&store.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
    }

    // ── verify_or_reject: fail-closed issuer + audience gate ──────────────

    #[test]
    fn verify_or_reject_rejects_unpinned_service() {
        let store = temp_store();
        let err = store
            .verify_or_reject("https://api.example.com", "https://idp", "aud")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unpinned"), "got: {err}");
    }

    #[test]
    fn verify_or_reject_accepts_exact_issuer_and_audience_match() {
        let store = temp_store();
        store
            .trust("https://api.example.com", "https://idp", "aud")
            .unwrap();
        store
            .verify_or_reject("https://api.example.com", "https://idp", "aud")
            .expect("matching issuer+audience must pass");
    }

    #[test]
    fn verify_or_reject_rejects_issuer_change() {
        let store = temp_store();
        store
            .trust("https://api.example.com", "https://idp", "aud")
            .unwrap();
        let err = store
            .verify_or_reject("https://api.example.com", "https://evil-idp", "aud")
            .unwrap_err()
            .to_string();
        assert!(err.contains("issuer changed"), "got: {err}");
    }

    #[test]
    fn verify_or_reject_rejects_audience_change() {
        let store = temp_store();
        store
            .trust("https://api.example.com", "https://idp", "aud")
            .unwrap();
        let err = store
            .verify_or_reject("https://api.example.com", "https://idp", "other-aud")
            .unwrap_err()
            .to_string();
        assert!(err.contains("audience changed"), "got: {err}");
    }

    #[test]
    fn verify_or_reject_rejects_legacy_entry_without_issuer() {
        // Simulate a pre-issuer trust file: KnownService with an empty issuer
        // (the #[serde(default)] path). It must fail closed until re-trusted.
        let store = temp_store();
        let legacy = HashMap::from([(
            "https://api.example.com".to_string(),
            KnownService {
                issuer: String::new(),
                audience: "aud".to_string(),
                first_seen: now_rfc3339(),
                last_seen: now_rfc3339(),
            },
        )]);
        store.save_locked(&legacy).unwrap();

        let err = store
            .verify_or_reject("https://api.example.com", "https://idp", "aud")
            .unwrap_err()
            .to_string();
        assert!(err.contains("without an issuer"), "got: {err}");

        // Re-trusting upgrades the pin and then it passes.
        store
            .trust("https://api.example.com", "https://idp", "aud")
            .unwrap();
        store
            .verify_or_reject("https://api.example.com", "https://idp", "aud")
            .expect("re-trust upgrades the legacy pin");
    }

    #[test]
    fn legacy_audience_only_json_still_deserializes() {
        // A trust file written before issuer pinning has no `issuer` key.
        let store = temp_store();
        let legacy_json = r#"{
            "https://api.example.com": {
                "audience": "aud",
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": "2024-01-01T00:00:00Z"
            }
        }"#;
        std::fs::write(&store.path, legacy_json).unwrap();
        // verify() still works against the legacy entry: the empty stored
        // issuer skips the issuer comparison rather than reporting a change.
        let result = store
            .verify("https://api.example.com", "https://idp", "aud")
            .unwrap();
        assert!(matches!(result, TofuResult::Trusted));
    }
}

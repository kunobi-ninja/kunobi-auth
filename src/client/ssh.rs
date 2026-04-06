//! SSH key-based authentication provider.
//!
//! Reads a private key from `~/.ssh/id_ed25519` and produces an
//! `SSH-Signature` HTTP header that can be verified by the server-side
//! middleware.

use anyhow::{Context, Result};
use base64::Engine as _;
use ssh_encoding::Encode;
use ssh_key::{HashAlg, PublicKey};

/// Information about an SSH key found in `~/.ssh/`.
#[derive(Debug, Clone)]
pub struct SshKeyInfo {
    pub fingerprint: String,
    pub comment: String,
    pub key_type: String,
}

/// SSH private-key-based authentication provider.
///
/// By default the provider reads `~/.ssh/id_ed25519`.  If a fingerprint is
/// supplied, the loaded key is verified to match before signing.
pub struct SshAgentAuth {
    /// Optional fingerprint constraint (`"SHA256:…"`). When `None`, any
    /// key found at the default path is accepted.
    fingerprint: Option<String>,
}

impl SshAgentAuth {
    /// Create a new provider. Pass `Some(fingerprint)` to pin a specific key.
    pub fn new(fingerprint: Option<String>) -> Self {
        Self { fingerprint }
    }

    /// Scan `~/.ssh/` and return metadata for every Ed25519 public key found.
    pub fn list_keys(&self) -> Result<Vec<SshKeyInfo>> {
        let ssh_dir = dirs::home_dir()
            .context("No home directory found")?
            .join(".ssh");

        let mut keys = Vec::new();

        for entry in std::fs::read_dir(&ssh_dir)
            .with_context(|| format!("Failed to read {}", ssh_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();

            // Only look at .pub files.
            if path.extension().map_or(false, |e| e == "pub") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let content = content.trim().to_string();
                    if content.starts_with("ssh-ed25519") {
                        if let Ok(key) = PublicKey::from_openssh(&content) {
                            keys.push(SshKeyInfo {
                                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                                comment: key.comment().to_string(),
                                key_type: "ssh-ed25519".to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Build a complete `SSH-Signature` HTTP header value.
    ///
    /// Loads `~/.ssh/id_ed25519`, signs the canonical request message, and
    /// returns a header string of the form:
    /// ```text
    /// SSH-Signature fingerprint="…",timestamp="…",nonce="…",signature="…"
    /// ```
    pub fn authorize(
        &self,
        namespace: &str,
        method: &str,
        path_with_query: &str,
        body: &[u8],
    ) -> Result<String> {
        // Load private key.
        let key_path = dirs::home_dir()
            .context("No home directory found")?
            .join(".ssh/id_ed25519");

        let key_data = std::fs::read_to_string(&key_path)
            .with_context(|| format!("Failed to read {}", key_path.display()))?;

        let private_key = ssh_key::PrivateKey::from_openssh(&key_data)
            .context("Failed to parse SSH private key from ~/.ssh/id_ed25519")?;

        // Optionally verify fingerprint.
        let actual_fp = private_key.fingerprint(HashAlg::Sha256).to_string();
        if let Some(ref wanted_fp) = self.fingerprint {
            if &actual_fp != wanted_fp {
                anyhow::bail!(
                    "Key fingerprint mismatch: wanted {wanted_fp}, got {actual_fp}"
                );
            }
        }

        // Build canonical signed message.
        // The server parses the timestamp as a unix epoch integer, so we must
        // produce one here (not RFC3339).
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("System clock error")?
            .as_secs()
            .to_string();

        let nonce = uuid::Uuid::new_v4().to_string();

        let message = crate::server::ssh::build_signed_message(
            &timestamp,
            &nonce,
            method,
            path_with_query,
            body,
        );

        // Sign with SSHSIG.
        let sshsig = private_key
            .sign(namespace, HashAlg::Sha512, &message)
            .context("Failed to sign message with SSH key")?;

        // Encode SSHSIG to binary, then base64.
        let mut sig_bytes = Vec::new();
        sshsig
            .encode(&mut sig_bytes)
            .context("Failed to encode SSHSIG")?;

        let sig_b64 =
            base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        Ok(format!(
            r#"SSH-Signature fingerprint="{actual_fp}",timestamp="{timestamp}",nonce="{nonce}",signature="{sig_b64}""#,
        ))
    }
}

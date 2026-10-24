//! SSH key-based authentication provider.
//!
//! Supports two modes:
//! 1. **SSH agent** (preferred): connects to `SSH_AUTH_SOCK` to list keys and sign.
//! 2. **Direct key file**: reads `~/.ssh/id_ed25519` as fallback.

use anyhow::{Context, Result};
use base64::Engine as _;
use ssh_agent_client_rs::Identity;
use ssh_encoding::Encode;
use ssh_key::{HashAlg, PublicKey, SshSig};

/// Information about an SSH key.
#[derive(Debug, Clone)]
pub struct SshKeyInfo {
    /// Key fingerprint identifying the key.
    pub fingerprint: String,
    /// Comment from the key entry.
    pub comment: String,
    /// Key type string.
    pub key_type: String,
}

/// SSH authentication provider.
///
/// If `SSH_AUTH_SOCK` is set, uses the SSH agent for key listing and signing.
/// Otherwise falls back to reading `~/.ssh/id_ed25519` directly.
pub struct SshAgentAuth {
    /// Optional fingerprint constraint (`"SHA256:…"`). When `None`, uses the
    /// first Ed25519 key found.
    fingerprint: Option<String>,
}

impl SshAgentAuth {
    /// Create a new provider. Pass `Some(fingerprint)` to pin a specific key.
    pub fn new(fingerprint: Option<String>) -> Self {
        Self { fingerprint }
    }

    /// List available Ed25519 keys (from agent or ~/.ssh/*.pub files).
    pub fn list_keys(&self) -> Result<Vec<SshKeyInfo>> {
        if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
            self.list_keys_from_agent(&sock)
        } else {
            self.list_keys_from_files()
        }
    }

    /// Build a complete `SSH-Signature` HTTP header value.
    ///
    /// Uses the SSH agent if `SSH_AUTH_SOCK` is set, otherwise reads the
    /// private key file directly.
    pub fn authorize(
        &self,
        namespace: &str,
        method: &str,
        path_with_query: &str,
        body: &[u8],
    ) -> Result<String> {
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

        let (fingerprint, sig_bytes) = if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
            self.sign_with_agent(&sock, namespace, &message)?
        } else {
            self.sign_with_key_file(namespace, &message)?
        };

        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        Ok(format!(
            r#"SSH-Signature fingerprint="{fingerprint}",timestamp="{timestamp}",nonce="{nonce}",signature="{sig_b64}""#,
        ))
    }

    // --- Agent-based signing ---

    fn list_keys_from_agent(&self, sock: &str) -> Result<Vec<SshKeyInfo>> {
        let mut agent = ssh_agent_client_rs::Client::connect(std::path::Path::new(sock))
            .context("Failed to connect to SSH agent")?;

        let identities = agent
            .list_all_identities()
            .context("Failed to list SSH agent keys")?;

        Ok(identities
            .iter()
            .filter_map(|id| match id {
                Identity::PublicKey(pk) if pk.algorithm() == ssh_key::Algorithm::Ed25519 => {
                    Some(SshKeyInfo {
                        fingerprint: pk.fingerprint(HashAlg::Sha256).to_string(),
                        comment: pk.comment().to_string(),
                        key_type: "ssh-ed25519".to_string(),
                    })
                }
                _ => None,
            })
            .collect())
    }

    fn sign_with_agent(
        &self,
        sock: &str,
        namespace: &str,
        message: &[u8],
    ) -> Result<(String, Vec<u8>)> {
        let mut agent = ssh_agent_client_rs::Client::connect(std::path::Path::new(sock))
            .context("Failed to connect to SSH agent")?;

        let identities = agent
            .list_all_identities()
            .context("Failed to list SSH agent keys")?;

        // Find the right Ed25519 key
        let (identity, public_key) = self.find_ed25519_identity(&identities)?;
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();

        // Compute the SSHSIG "signed data" — the bytes the agent needs to sign.
        // This is the internal representation that SSHSIG signs over (includes
        // the SSHSIG preamble, namespace, hash algorithm, and message hash).
        let signed_data = SshSig::signed_data(namespace, HashAlg::Sha512, message)
            .map_err(|e| anyhow::anyhow!("Failed to build SSHSIG signed data: {e}"))?;

        // Ask the agent to sign the SSHSIG signed data
        let raw_signature = agent
            .sign_with_ref(identity, &signed_data)
            .context("SSH agent signing failed")?;

        // Wrap the raw signature in an SSHSIG envelope
        let sshsig = SshSig::new(
            public_key.key_data().clone(),
            namespace,
            HashAlg::Sha512,
            raw_signature,
        )
        .map_err(|e| anyhow::anyhow!("Failed to construct SSHSIG envelope: {e}"))?;

        // Encode to binary
        let mut sig_bytes = Vec::new();
        sshsig
            .encode(&mut sig_bytes)
            .context("Failed to encode SSHSIG")?;

        Ok((fingerprint, sig_bytes))
    }

    // --- File-based signing (fallback) ---

    fn list_keys_from_files(&self) -> Result<Vec<SshKeyInfo>> {
        let ssh_dir = dirs::home_dir()
            .context("No home directory found")?
            .join(".ssh");

        let mut keys = Vec::new();
        let entries = std::fs::read_dir(&ssh_dir)
            .with_context(|| format!("Failed to read {}", ssh_dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "pub")
                && let Ok(content) = std::fs::read_to_string(&path)
            {
                let content = content.trim().to_string();
                if content.starts_with("ssh-ed25519")
                    && let Ok(key) = PublicKey::from_openssh(&content)
                {
                    keys.push(SshKeyInfo {
                        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                        comment: key.comment().to_string(),
                        key_type: "ssh-ed25519".to_string(),
                    });
                }
            }
        }
        Ok(keys)
    }

    fn sign_with_key_file(&self, namespace: &str, message: &[u8]) -> Result<(String, Vec<u8>)> {
        let key_path = dirs::home_dir()
            .context("No home directory found")?
            .join(".ssh/id_ed25519");

        let key_data = std::fs::read_to_string(&key_path)
            .with_context(|| format!("Failed to read {}", key_path.display()))?;

        let private_key = ssh_key::PrivateKey::from_openssh(&key_data)
            .context("Failed to parse SSH private key")?;

        if let Some(ref wanted_fp) = self.fingerprint {
            let actual_fp = private_key.fingerprint(HashAlg::Sha256).to_string();
            if &actual_fp != wanted_fp {
                anyhow::bail!("Key fingerprint mismatch: wanted {wanted_fp}, got {actual_fp}");
            }
        }

        let fingerprint = private_key.fingerprint(HashAlg::Sha256).to_string();

        let sshsig = private_key
            .sign(namespace, HashAlg::Sha512, message)
            .map_err(|e| anyhow::anyhow!("Failed to sign: {e}"))?;

        let mut sig_bytes = Vec::new();
        sshsig
            .encode(&mut sig_bytes)
            .context("Failed to encode SSHSIG")?;

        Ok((fingerprint, sig_bytes))
    }

    // --- Helpers ---

    fn find_ed25519_identity<'a>(
        &self,
        identities: &'a [Identity<'static>],
    ) -> Result<(&'a Identity<'static>, &'a PublicKey)> {
        for identity in identities {
            let pk = match identity {
                Identity::PublicKey(pk) => pk.as_ref().as_ref(),
                _ => continue,
            };
            if pk.algorithm() != ssh_key::Algorithm::Ed25519 {
                continue;
            }
            let fp = pk.fingerprint(HashAlg::Sha256).to_string();
            if let Some(ref wanted) = self.fingerprint {
                if &fp == wanted {
                    return Ok((identity, pk));
                }
            } else {
                return Ok((identity, pk));
            }
        }
        match &self.fingerprint {
            Some(fp) => anyhow::bail!("No Ed25519 key with fingerprint {fp} found in SSH agent"),
            None => anyhow::bail!("No Ed25519 keys found in SSH agent"),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use ssh_encoding::Decode;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};

    fn ssh_string(bytes: &[u8], output: &mut Vec<u8>) {
        output.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        output.extend_from_slice(bytes);
    }

    fn read_packet(socket: &mut impl Read) -> Vec<u8> {
        let mut size = [0; 4];
        socket.read_exact(&mut size).unwrap();
        let size = u32::from_be_bytes(size) as usize;
        assert!(size <= 4096);
        let mut payload = vec![0; size];
        socket.read_exact(&mut payload).unwrap();
        payload
    }

    fn write_packet(socket: &mut impl Write, payload: &[u8]) {
        let mut packet = Vec::new();
        ssh_string(payload, &mut packet);
        socket.write_all(&packet).unwrap();
    }

    #[test]
    fn agent_signing_selects_ed25519_from_mixed_keys_and_verifies_sshsig() {
        let private_key =
            ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let namespace = "kunobi-agent-test";
        let message = b"request body signed by the synthetic agent";
        let expected = private_key
            .sign(namespace, HashAlg::Sha512, message)
            .unwrap();

        // Keep the Unix socket path short enough for macOS. No process
        // environment or real SSH agent is used by this test.
        let directory = tempfile::Builder::new()
            .prefix("ka-ssh-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket_path = directory.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let agent_key = public_key.clone();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut socket, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "synthetic SSH agent timed out waiting for a connection"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("synthetic SSH agent accept failed: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            assert_eq!(read_packet(&mut socket), [11]);

            // ECDSA parsing must work before the client can select Ed25519.
            let other_key = PublicKey::from_openssh(
                "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHxUGDfJZXgCXPMYfKhFMWbHd/F6OJgGsUIMDJYJGzaLLQDn7JDLZ8uS3Z4ZJgU9XdVPvIKW+L6m4GJBgMilAck= test@example.com",
            )
            .unwrap();
            let mut identities = vec![12];
            identities.extend_from_slice(&2_u32.to_be_bytes());
            for key in [&other_key, &agent_key] {
                ssh_string(&key.to_bytes().unwrap(), &mut identities);
                ssh_string(key.comment().as_bytes(), &mut identities);
            }
            write_packet(&mut socket, &identities);

            let mut request = vec![13];
            ssh_string(&agent_key.to_bytes().unwrap(), &mut request);
            ssh_string(
                &SshSig::signed_data(namespace, HashAlg::Sha512, message).unwrap(),
                &mut request,
            );
            request.extend_from_slice(&0_u32.to_be_bytes());
            assert_eq!(read_packet(&mut socket), request);

            let mut signature = Vec::new();
            expected.signature().encode(&mut signature).unwrap();
            let mut response = vec![14];
            ssh_string(&signature, &mut response);
            write_packet(&mut socket, &response);
        });

        let result = SshAgentAuth::new(Some(fingerprint.clone())).sign_with_agent(
            socket_path.to_str().unwrap(),
            namespace,
            message,
        );
        server.join().unwrap();
        let (actual_fingerprint, bytes) = result.unwrap();
        assert_eq!(actual_fingerprint, fingerprint);
        let signature = SshSig::decode(&mut bytes.as_slice()).unwrap();
        public_key.verify(namespace, message, &signature).unwrap();
        assert!(
            public_key
                .verify(namespace, b"changed body", &signature)
                .is_err()
        );
        assert!(
            public_key
                .verify("other-namespace", message, &signature)
                .is_err()
        );
    }
}

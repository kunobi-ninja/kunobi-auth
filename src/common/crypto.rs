//! Process-level jsonwebtoken crypto provider selection.

/// Ensure a process-level jsonwebtoken [`CryptoProvider`] is installed.
///
/// Cargo unifies features across the whole dependency graph: when both
/// `rust_crypto` and `aws_lc_rs` end up enabled (e.g. a desktop app that links
/// aws-lc-rs via rustls while this crate defaults to `rust_crypto`),
/// jsonwebtoken 10 cannot auto-select a provider and panics on first
/// signer/verifier use. Installing one explicitly before our own JWT
/// operations makes validation deterministic for every consumer.
///
/// A provider already installed by the application wins: `install_default`
/// returns `Err` if one is set, which we deliberately ignore. When both crate
/// features are enabled we prefer `rust_crypto`, matching this crate's
/// historical default. With neither feature enabled this is a no-op and the
/// consumer must call `CryptoProvider::install_default()` themselves (see
/// `Cargo.toml`).
///
/// [`CryptoProvider`]: jsonwebtoken::crypto::CryptoProvider
pub fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        #[cfg(feature = "rust_crypto")]
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
        #[cfg(all(feature = "aws_lc_rs", not(feature = "rust_crypto")))]
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

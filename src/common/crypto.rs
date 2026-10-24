//! Process-level jsonwebtoken crypto provider selection.

#[cfg(feature = "rust_crypto")]
mod rust_crypto;

/// Ensure a process-level jsonwebtoken [`CryptoProvider`] is installed.
///
/// Cargo unifies jsonwebtoken features across the dependency graph. Install the
/// selected provider before the first JWT operation, including builds that
/// enable both auth provider features.
///
/// A provider already installed by the application wins. When both crate
/// features are enabled we prefer `rust_crypto`, matching this crate's
/// historical default. With neither enabled this is a no-op, and the application
/// must install a provider itself.
///
/// With `rust_crypto`, call this before using jsonwebtoken directly as well.
/// This crate installs its own RustCrypto provider through jsonwebtoken's public
/// extension API and does not enable jsonwebtoken's built-in RustCrypto feature.
///
/// [`CryptoProvider`]: jsonwebtoken::crypto::CryptoProvider
pub fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        #[cfg(feature = "rust_crypto")]
        let _ = rust_crypto::DEFAULT_PROVIDER.install_default();
        #[cfg(all(feature = "aws_lc_rs", not(feature = "rust_crypto")))]
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

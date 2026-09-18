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

/// Fail clearly when outbound HTTP has no TLS provider.
///
/// With the `aws-lc-tls` feature, reqwest brings its own rustls provider and
/// this is a no-op. Without it (the `-core` features, or `default-features =
/// false` with no feature that implies it), the application must install a
/// rustls [`CryptoProvider`] before kunobi-auth builds an HTTP client;
/// otherwise reqwest panics with a message that does not say why. Call this
/// right before every `reqwest::Client::builder()`.
///
/// [`CryptoProvider`]: https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html
pub(crate) fn require_tls_provider() {
    #[cfg(not(feature = "aws-lc-tls"))]
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        panic!(
            "kunobi-auth: no rustls CryptoProvider is installed for outbound HTTPS. \
             Enable the `aws-lc-tls` feature, or install a provider before building an \
             HTTP client or JwksManager, e.g. \
             `rustls::crypto::ring::default_provider().install_default()`"
        );
    }
}

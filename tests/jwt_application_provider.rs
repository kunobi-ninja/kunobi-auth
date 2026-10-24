#![cfg(any(feature = "rust_crypto", feature = "aws_lc_rs"))]

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey,
    crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils, sign},
    errors::{ErrorKind, Result},
};

fn application_signer(_: &Algorithm, _: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    Err(ErrorKind::InvalidAlgorithm.into())
}

fn application_verifier(_: &Algorithm, _: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    Err(ErrorKind::InvalidAlgorithm.into())
}

static APPLICATION_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: application_signer,
    verifier_factory: application_verifier,
    key_utils: KeyUtils::new_unimplemented(),
};

// This integration test has its own process and therefore its own provider OnceLock.
#[test]
fn an_application_installed_provider_keeps_precedence() {
    APPLICATION_PROVIDER.install_default().unwrap();
    kunobi_auth::ensure_crypto_provider();
    kunobi_auth::ensure_crypto_provider();
    let error = sign(
        b"message",
        &EncodingKey::from_secret(b"secret"),
        Algorithm::HS256,
    )
    .unwrap_err();
    assert_eq!(error.into_kind(), ErrorKind::InvalidAlgorithm);
}

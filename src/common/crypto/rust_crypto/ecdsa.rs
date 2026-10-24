// Copyright (c) 2015 Vincent Prouillet
// SPDX-License-Identifier: MIT
// Adapted from jsonwebtoken 11.1.0, revision 4c0ae752e9acc108c8e2c4c8ed8128dc66014210.
// See LICENSES/jsonwebtoken-MIT.

//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! ECDSA family of algorithms using RustCrypto

use jsonwebtoken::AlgorithmFamily;
use jsonwebtoken::crypto::{JwtSigner, JwtVerifier};
use jsonwebtoken::errors::{ErrorKind, Result, new_error};
use jsonwebtoken::signature::{Error, Signer, Verifier};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use jwt_p256 as p256;
use jwt_p384 as p384;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{
    Signature as Signature256, SigningKey as SigningKey256, VerifyingKey as VerifyingKey256,
};
use p256::pkcs8::DecodePrivateKey;
use p384::ecdsa::{
    Signature as Signature384, SigningKey as SigningKey384, VerifyingKey as VerifyingKey384,
};

macro_rules! define_ecdsa_signer {
    ($name:ident, $alg:expr, $signing_key:ty) => {
        pub struct $name($signing_key);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family() != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    <$signing_key>::from_pkcs8_der(encoding_key.as_bytes())
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let signature = self.0.sign_recoverable(msg).0;
                Ok(signature.to_vec())
            }
        }

        impl JwtSigner for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

macro_rules! define_ecdsa_verifier {
    ($name:ident, $alg:expr, $verifying_key:ty, $signature:ty) => {
        pub struct $name($verifying_key);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    <$verifying_key>::from_sec1_bytes(decoding_key.try_get_as_bytes()?)
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                self.0
                    .verify(
                        msg,
                        &<$signature>::from_slice(signature).map_err(Error::from_source)?,
                    )
                    .map_err(Error::from_source)?;
                Ok(())
            }
        }

        impl JwtVerifier for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

define_ecdsa_signer!(Es256Signer, Algorithm::ES256, SigningKey256);
define_ecdsa_signer!(Es384Signer, Algorithm::ES384, SigningKey384);

define_ecdsa_verifier!(
    Es256Verifier,
    Algorithm::ES256,
    VerifyingKey256,
    Signature256
);
define_ecdsa_verifier!(
    Es384Verifier,
    Algorithm::ES384,
    VerifyingKey384,
    Signature384
);

// Copyright (c) 2015 Vincent Prouillet
// SPDX-License-Identifier: MIT
// Adapted from jsonwebtoken 11.1.0, revision 4c0ae752e9acc108c8e2c4c8ed8128dc66014210.
// See LICENSES/jsonwebtoken-MIT.

//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for EdDSA using RustCrypto.

use jsonwebtoken::AlgorithmFamily;
use jsonwebtoken::crypto::{JwtSigner, JwtVerifier};
use jsonwebtoken::errors::{ErrorKind, Result, new_error};
use jsonwebtoken::signature::{Error, Signer, Verifier};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use jwt_ed25519_dalek::pkcs8::DecodePrivateKey;
use jwt_ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

pub struct EdDSASigner(SigningKey);

impl EdDSASigner {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family() != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            SigningKey::from_pkcs8_der(encoding_key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ))
    }
}

impl Signer<Vec<u8>> for EdDSASigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        Ok(self.0.sign(msg).to_bytes().to_vec())
    }
}

impl JwtSigner for EdDSASigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

pub struct EdDSAVerifier(VerifyingKey);

impl EdDSAVerifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family() != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            VerifyingKey::from_bytes(
                <&[u8; 32]>::try_from(
                    decoding_key
                        .try_get_as_bytes()?
                        .get(..32)
                        .ok_or(ErrorKind::InvalidEddsaKey)?,
                )
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
            )
            .map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ))
    }
}

impl Verifier<Vec<u8>> for EdDSAVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        self.0
            .verify(
                msg,
                &Signature::from_slice(signature).map_err(Error::from_source)?,
            )
            .map_err(Error::from_source)?;
        Ok(())
    }
}

impl JwtVerifier for EdDSAVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

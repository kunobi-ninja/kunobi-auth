#![cfg(any(feature = "rust_crypto", feature = "aws_lc_rs"))]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation,
    crypto::{sign, verify},
    decode, encode,
    errors::ErrorKind,
    jwk::{Jwk, ThumbprintHash},
};

const ALGORITHMS: [Algorithm; 12] = [
    Algorithm::HS256,
    Algorithm::HS384,
    Algorithm::HS512,
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

// RFC 6979 A.2.5/A.2.6 public keys, distinct from the upstream PEM fixtures.
const P256_PUBLIC: &str = concat!(
    "04",
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
);
const P384_PUBLIC: &str = concat!(
    "04",
    "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13",
    "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
);

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

fn keys(algorithm: Algorithm) -> (EncodingKey, DecodingKey, DecodingKey) {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => (
            EncodingKey::from_secret(b"migration test secret"),
            DecodingKey::from_secret(b"migration test secret"),
            DecodingKey::from_secret(b"different secret"),
        ),
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => (
            EncodingKey::from_rsa_pem(include_bytes!("jwt-crypto/rsa/private_rsa_key_pkcs1.pem"))
                .unwrap(),
            DecodingKey::from_rsa_pem(include_bytes!("jwt-crypto/rsa/public_rsa_key_pkcs1.pem"))
                .unwrap(),
            DecodingKey::from_rsa_pem(include_bytes!("jwt-crypto/rsa/public_jwtio.pem")).unwrap(),
        ),
        Algorithm::ES256 => (
            EncodingKey::from_ec_pem(include_bytes!("jwt-crypto/ecdsa/private_ecdsa_key.pem"))
                .unwrap(),
            DecodingKey::from_ec_pem(include_bytes!("jwt-crypto/ecdsa/public_ecdsa_key.pem"))
                .unwrap(),
            DecodingKey::from_ec_der(&unhex(P256_PUBLIC)),
        ),
        Algorithm::ES384 => (
            EncodingKey::from_ec_pem(include_bytes!("jwt-crypto/ecdsa/private_jwtio_pkcs8.pem"))
                .unwrap(),
            DecodingKey::from_ec_pem(include_bytes!("jwt-crypto/ecdsa/public_jwtio.pem")).unwrap(),
            DecodingKey::from_ec_der(&unhex(P384_PUBLIC)),
        ),
        Algorithm::EdDSA => (
            EncodingKey::from_ed_pem(include_bytes!("jwt-crypto/eddsa/private_ed25519_key.pem"))
                .unwrap(),
            DecodingKey::from_ed_pem(include_bytes!("jwt-crypto/eddsa/public_ed25519_key.pem"))
                .unwrap(),
            DecodingKey::from_ed_der(&unhex(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            )),
        ),
        _ => panic!("unsupported test algorithm: {algorithm:?}"),
    }
}

#[test]
fn every_algorithm_preserves_jwt_acceptance_and_rejection() {
    kunobi_auth::ensure_crypto_provider();
    let claims = serde_json::json!({"sub": "migration-control", "exp": 4_102_444_800_u64});

    for algorithm in ALGORITHMS {
        let (encoding_key, decoding_key, wrong_key) = keys(algorithm);
        let token = encode(&Header::new(algorithm), &claims, &encoding_key).unwrap();
        let validation = Validation::new(algorithm);
        let decoded = decode::<serde_json::Value>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(decoded.claims, claims, "{algorithm:?}");
        assert_eq!(decoded.header.alg, algorithm);
        assert!(decode::<serde_json::Value>(&token, &wrong_key, &validation).is_err());

        let signature_start = token.rfind('.').unwrap() + 1;
        let mut corrupted = token.clone().into_bytes();
        corrupted[signature_start] = if corrupted[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let corrupted = String::from_utf8(corrupted).unwrap();
        assert!(decode::<serde_json::Value>(&corrupted, &decoding_key, &validation).is_err());

        let other_algorithm = if algorithm == Algorithm::HS256 {
            Algorithm::HS384
        } else {
            Algorithm::HS256
        };
        assert_eq!(
            decode::<serde_json::Value>(&token, &decoding_key, &Validation::new(other_algorithm))
                .unwrap_err()
                .into_kind(),
            ErrorKind::InvalidAlgorithm,
        );
        let wrong_family = if matches!(
            algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            EncodingKey::from_rsa_der(b"not an RSA key")
        } else {
            EncodingKey::from_secret(b"not an asymmetric key")
        };
        assert!(encode(&Header::new(algorithm), &claims, &wrong_family).is_err());
    }
}

#[test]
fn private_key_jwks_preserve_components_and_thumbprints() {
    kunobi_auth::ensure_crypto_provider();
    for algorithm in [
        Algorithm::RS256,
        Algorithm::ES256,
        Algorithm::ES384,
        Algorithm::EdDSA,
    ] {
        let (encoding_key, _, _) = keys(algorithm);
        let jwk = Jwk::from_encoding_key(&encoding_key, algorithm).unwrap();
        let decoding_key = DecodingKey::from_jwk(&jwk).unwrap();
        let token = encode(
            &Header::new(algorithm),
            &serde_json::json!({"sub": "jwk-control", "exp": 4_102_444_800_u64}),
            &encoding_key,
        )
        .unwrap();
        decode::<serde_json::Value>(&token, &decoding_key, &Validation::new(algorithm)).unwrap();
        for (hash, expected_bytes) in [
            (ThumbprintHash::SHA256, 32),
            (ThumbprintHash::SHA384, 48),
            (ThumbprintHash::SHA512, 64),
        ] {
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(jwk.thumbprint(hash).unwrap())
                    .unwrap()
                    .len(),
                expected_bytes
            );
        }
    }
}

#[test]
fn hmac_matches_rfc4231_case_one() {
    kunobi_auth::ensure_crypto_provider();
    let key = EncodingKey::from_secret(&[0x0b; 20]);
    for (algorithm, expected) in [
        (
            Algorithm::HS256,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            Algorithm::HS384,
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        ),
        (
            Algorithm::HS512,
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
    ] {
        let signature = sign(b"Hi There", &key, algorithm).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(signature).unwrap(), unhex(expected));
    }
}

#[test]
fn ecdsa_verifies_rfc6979_and_eddsa_verifies_rfc8032() {
    kunobi_auth::ensure_crypto_provider();
    for (algorithm, public, signature) in [
        (
            Algorithm::ES256,
            P256_PUBLIC,
            concat!(
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            ),
        ),
        (
            Algorithm::ES384,
            P384_PUBLIC,
            concat!(
                "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46",
                "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
            ),
        ),
    ] {
        let signature = URL_SAFE_NO_PAD.encode(unhex(signature));
        let key = DecodingKey::from_ec_der(&unhex(public));
        assert!(verify(&signature, b"sample", &key, algorithm).unwrap());
        assert!(!verify(&signature, b"different", &key, algorithm).unwrap());
        assert!(
            !verify(
                &URL_SAFE_NO_PAD.encode([0_u8; 1]),
                b"sample",
                &key,
                algorithm
            )
            .unwrap()
        );
    }

    let key = DecodingKey::from_ed_der(&unhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ));
    let signature = URL_SAFE_NO_PAD.encode(unhex(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )));
    assert!(verify(&signature, b"", &key, Algorithm::EdDSA).unwrap());
    assert!(!verify(&signature, b"changed", &key, Algorithm::EdDSA).unwrap());
}

#[cfg(feature = "rust_crypto")]
#[test]
fn short_eddsa_keys_return_an_error_instead_of_panicking() {
    kunobi_auth::ensure_crypto_provider();
    for length in 0..32 {
        let key = DecodingKey::from_ed_der(&vec![0; length]);
        let error = verify("AA", b"message", &key, Algorithm::EdDSA).unwrap_err();
        assert_eq!(error.into_kind(), ErrorKind::InvalidEddsaKey);
    }
}

#[test]
fn provider_refuses_valid_key_material_with_the_wrong_key_family() {
    kunobi_auth::ensure_crypto_provider();
    let message = b"key family admission control";
    for algorithm in ALGORITHMS {
        let (encoding_key, decoding_key, _) = keys(algorithm);
        let public_bytes = decoding_key.try_get_as_bytes().unwrap();
        let (wrong_encoding_family, wrong_decoding_family) = if matches!(
            algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            (
                EncodingKey::from_rsa_der(encoding_key.as_bytes()),
                DecodingKey::from_rsa_der(public_bytes),
            )
        } else {
            (
                EncodingKey::from_secret(encoding_key.as_bytes()),
                DecodingKey::from_secret(public_bytes),
            )
        };
        // The bytes stay valid for the algorithm. Only the declared family changes.
        let signature = sign(message, &encoding_key, algorithm).unwrap();
        assert!(verify(&signature, message, &decoding_key, algorithm).unwrap());
        assert!(sign(message, &wrong_encoding_family, algorithm).is_err());
        assert!(verify(&signature, message, &wrong_decoding_family, algorithm).is_err());
    }
}

#[test]
fn hmac_matches_rfc4231_case_two() {
    kunobi_auth::ensure_crypto_provider();
    let encoding_key = EncodingKey::from_secret(b"Jefe");
    let decoding_key = DecodingKey::from_secret(b"Jefe");
    let message = b"what do ya want for nothing?";
    for (algorithm, expected) in [
        (
            Algorithm::HS256,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            Algorithm::HS384,
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
        ),
        (
            Algorithm::HS512,
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
    ] {
        let signature = sign(message, &encoding_key, algorithm).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&signature).unwrap(), unhex(expected));
        assert!(verify(&signature, message, &decoding_key, algorithm).unwrap());
        assert!(!verify(&signature, b"changed", &decoding_key, algorithm).unwrap());
    }
}

#[test]
fn eddsa_verifies_rfc8032_case_two_and_refuses_malformed_signatures() {
    kunobi_auth::ensure_crypto_provider();
    let key = DecodingKey::from_ed_der(&unhex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ));
    let signature = unhex(concat!(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ));
    let encoded = URL_SAFE_NO_PAD.encode(&signature);
    assert!(verify(&encoded, &[0x72], &key, Algorithm::EdDSA).unwrap());
    assert!(!verify(&encoded, &[0x73], &key, Algorithm::EdDSA).unwrap());
    for malformed in [&signature[..63], &[0_u8; 64][..]] {
        assert!(
            !verify(
                &URL_SAFE_NO_PAD.encode(malformed),
                &[0x72],
                &key,
                Algorithm::EdDSA,
            )
            .unwrap()
        );
    }
}

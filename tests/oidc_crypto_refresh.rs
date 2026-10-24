//! Exercise the OIDC verifier through discovery, JWKS and refresh exchange.
#![cfg(all(
    feature = "client-core",
    feature = "server",
    any(feature = "rust_crypto", feature = "aws_lc_rs")
))]

use axum::extract::Form;
use axum::routing::{get, post};
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use kunobi_auth::client::oidc;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// Public test key also used by proptest_jwt.rs. Never use a real login or key.
const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjCZ3enwwbi1sTMaE
CIAe12xZratKWzRoekhOUBIDCZChRANCAAQitjpgInyqDv9dQ4D0FZ4SiZX+KaqP
4uS/qxtTQoPfLryamFKS8SYa/uu0hcS+ASwxyTxsMBNuMpdBBC+mLBOO
-----END PRIVATE KEY-----
";
const TEST_CLIENT: &str = "crypto-refresh-test";
const OLD_REFRESH_TOKEN: &str = "synthetic-refresh-token";

#[derive(Clone, Copy, Debug)]
enum TokenCase {
    Valid,
    WrongIssuer,
    WrongAudience,
    Expired,
    WrongKey,
    BadSignature,
    WrongAlgorithm,
}

struct TestProvider {
    issuer: String,
    id_token: String,
    expires_at: i64,
    requests: Arc<Mutex<Vec<HashMap<String, String>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestProvider {
    async fn start(case: TokenCase, rotated_refresh: Option<&str>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + 600;
        let mut claims = json!({
            "iss": issuer,
            "aud": TEST_CLIENT,
            "sub": "test-user",
            "iat": now,
            "exp": expires_at,
        });
        match case {
            TokenCase::WrongIssuer => claims["iss"] = json!("https://other.example.com"),
            TokenCase::WrongAudience => claims["aud"] = json!("another-client"),
            TokenCase::Expired => claims["exp"] = json!(now - 600),
            _ => {}
        }

        kunobi_auth::ensure_crypto_provider();
        let (algorithm, key) = if matches!(case, TokenCase::WrongAlgorithm) {
            (Algorithm::HS256, EncodingKey::from_secret(b"test-secret"))
        } else {
            (
                Algorithm::ES256,
                EncodingKey::from_ec_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap(),
            )
        };
        let mut header = Header::new(algorithm);
        header.kid = Some("test-key".into());
        let mut id_token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        if matches!(case, TokenCase::BadSignature) {
            let (message, signature) = id_token.rsplit_once('.').unwrap();
            let replacement = if signature.starts_with('A') { "B" } else { "A" };
            id_token = format!("{message}.{replacement}{}", &signature[1..]);
        }

        let (x, y) = if matches!(case, TokenCase::WrongKey) {
            (
                "ivbIJC0b-Z0aJDsH3_r8B9nw7cPWm8OtGnybH8iS2k4",
                "7kdp3cRFJ1nrEmtVvburerJ8LvTd3pGv3GQ8PusCLew",
            )
        } else {
            (
                "IrY6YCJ8qg7_XUOA9BWeEomV_imqj-Lkv6sbU0KD3y4",
                "vJqYUpLxJhr-67SFxL4BLDHJPGwwE24yl0EEL6YsE44",
            )
        };
        let discovery = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "token_endpoint_auth_methods_supported": ["none"],
        });
        let jwks = json!({ "keys": [{
            "kty": "EC", "crv": "P-256", "kid": "test-key",
            "alg": "ES256", "use": "sig", "x": x, "y": y,
        }] });
        let mut tokens = json!({
            "access_token": "synthetic-access-token",
            "token_type": "Bearer",
            "id_token": id_token,
        });
        if let Some(refresh) = rotated_refresh {
            tokens["refresh_token"] = json!(refresh);
        }

        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded_requests = requests.clone();
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(discovery) }),
            )
            .route("/jwks", get(move || async move { Json(jwks) }))
            .route(
                "/token",
                post(move |Form(form): Form<HashMap<String, String>>| {
                    let requests = recorded_requests.clone();
                    let tokens = tokens.clone();
                    async move {
                        requests.lock().await.push(form);
                        Json(tokens)
                    }
                }),
            );
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            issuer,
            id_token,
            expires_at,
            requests,
            task,
        }
    }

    async fn refresh(&self) -> anyhow::Result<kunobi_auth::client::StoredToken> {
        oidc::refresh(
            &self.issuer,
            TEST_CLIENT,
            "http://127.0.0.1:8329/callback",
            OLD_REFRESH_TOKEN,
        )
        .await
    }
}

#[tokio::test]
async fn refresh_verifies_ec_tokens_and_preserves_refresh_rotation() {
    for rotated_refresh in [None, Some("rotated-synthetic-token")] {
        let provider = TestProvider::start(TokenCase::Valid, rotated_refresh).await;
        let token = provider.refresh().await.unwrap();
        assert_eq!(token.id_token, provider.id_token);
        assert_eq!(token.issuer, provider.issuer);
        assert_eq!(token.expires_at, Some(provider.expires_at));
        assert_eq!(
            token.refresh_token.as_deref(),
            Some(rotated_refresh.unwrap_or(OLD_REFRESH_TOKEN))
        );
        let requests = provider.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["grant_type"], "refresh_token");
        assert_eq!(requests[0]["client_id"], TEST_CLIENT);
        assert_eq!(requests[0]["refresh_token"], OLD_REFRESH_TOKEN);
    }
}

#[tokio::test]
async fn refresh_rejects_invalid_ec_tokens_and_algorithm_confusion() {
    for case in [
        TokenCase::WrongIssuer,
        TokenCase::WrongAudience,
        TokenCase::Expired,
        TokenCase::WrongKey,
        TokenCase::BadSignature,
        TokenCase::WrongAlgorithm,
    ] {
        let provider = TestProvider::start(case, None).await;
        let error = provider.refresh().await.unwrap_err();
        assert!(
            error.to_string().contains("ID token validation failed"),
            "{case:?}: {error:#}"
        );
    }
}

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::debug;

const JWKS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Minimum interval between forced JWKS refetches triggered by an unknown
/// `kid`. Prevents an attacker who sends garbage `kid` values from turning
/// the auth path into an amplification vector against the IdP.
const KID_MISS_REFRESH_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
    #[allow(dead_code)]
    crv: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

struct CachedJwks {
    keys: Vec<Jwk>,
    fetched_at: std::time::Instant,
}

/// JWKS key manager -- fetches and caches signing keys from OIDC providers.
pub struct JwksManager {
    http: reqwest::Client,
    cache: RwLock<HashMap<String, CachedJwks>>,
}

impl JwksManager {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");
        Self {
            http,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Validate a JWT and return its claims.
    ///
    /// Both `issuer` and `audience` are required and validated against the `iss`
    /// / `aud` claims. Pass at least one audience.
    pub async fn validate_jwt(
        &self,
        token: &str,
        jwks_url: &str,
        issuer: &str,
        audience: &[String],
        algorithms: &[String],
    ) -> Result<HashMap<String, serde_json::Value>> {
        if issuer.is_empty() {
            anyhow::bail!("issuer must be set; refusing to validate JWT without issuer binding");
        }
        if audience.is_empty() {
            anyhow::bail!(
                "audience must be set; refusing to validate JWT without audience binding"
            );
        }

        let header = decode_header(token).context("Invalid JWT header")?;
        let kid = header.kid.as_deref();

        let keys = self.get_keys(jwks_url, kid).await?;
        let key = find_matching_key(&keys, kid)?;

        let mut validation = Validation::new(parse_algorithm(algorithms)?);
        validation.set_audience(audience);
        validation.set_issuer(&[issuer]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let decoding_key = build_decoding_key(key)?;
        let token_data =
            decode::<HashMap<String, serde_json::Value>>(token, &decoding_key, &validation)
                .context("JWT validation failed")?;

        Ok(token_data.claims)
    }

    /// Fetch JWKS keys, optionally forcing a refetch when `wanted_kid` isn't in
    /// the cached set (capped by [`KID_MISS_REFRESH_COOLDOWN`]).
    async fn get_keys(&self, jwks_url: &str, wanted_kid: Option<&str>) -> Result<Vec<Jwk>> {
        // Check cache.
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(jwks_url) {
                let fresh = cached.fetched_at.elapsed() < JWKS_CACHE_TTL;
                let kid_present = match wanted_kid {
                    Some(kid) => cached.keys.iter().any(|k| k.kid.as_deref() == Some(kid)),
                    None => true,
                };
                let cooled_down = cached.fetched_at.elapsed() >= KID_MISS_REFRESH_COOLDOWN;
                if fresh && (kid_present || !cooled_down) {
                    return Ok(cached.keys.clone());
                }
            }
        }

        // Miss / stale / forced rotation refetch.
        debug!(url = %jwks_url, kid = ?wanted_kid, "Fetching JWKS");
        let response: JwksResponse = self
            .http
            .get(jwks_url)
            .send()
            .await
            .context("Failed to fetch JWKS")?
            .json()
            .await
            .context("Failed to parse JWKS")?;

        let keys = response.keys;
        self.cache.write().await.insert(
            jwks_url.to_string(),
            CachedJwks {
                keys: keys.clone(),
                fetched_at: std::time::Instant::now(),
            },
        );

        Ok(keys)
    }
}

impl Default for JwksManager {
    fn default() -> Self {
        Self::new()
    }
}

fn find_matching_key<'a>(keys: &'a [Jwk], kid: Option<&str>) -> Result<&'a Jwk> {
    if let Some(kid) = kid {
        keys.iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or_else(|| anyhow::anyhow!("No key found with kid: {kid}"))
    } else {
        keys.first()
            .ok_or_else(|| anyhow::anyhow!("JWKS has no keys"))
    }
}

fn parse_algorithm(algorithms: &[String]) -> Result<Algorithm> {
    let alg = algorithms.first().map(|s| s.as_str()).unwrap_or("RS256");
    match alg {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "EdDSA" => Ok(Algorithm::EdDSA),
        _ => anyhow::bail!("Unsupported algorithm: {alg}"),
    }
}

fn build_decoding_key(key: &Jwk) -> Result<DecodingKey> {
    match key.kty.as_str() {
        "RSA" => {
            let n = key
                .n
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("RSA key missing 'n'"))?;
            let e = key
                .e
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("RSA key missing 'e'"))?;
            Ok(DecodingKey::from_rsa_components(n, e)?)
        }
        "EC" => {
            let x = key
                .x
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("EC key missing 'x'"))?;
            let y = key
                .y
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("EC key missing 'y'"))?;
            Ok(DecodingKey::from_ec_components(x, y)?)
        }
        "OKP" => {
            let x = key
                .x
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("OKP key missing 'x'"))?;
            Ok(DecodingKey::from_ed_components(x)?)
        }
        kty => anyhow::bail!("Unsupported key type: {kty}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_algorithm_rs256() {
        let alg = parse_algorithm(&["RS256".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::RS256);
    }

    #[test]
    fn test_parse_algorithm_rs384() {
        let alg = parse_algorithm(&["RS384".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::RS384);
    }

    #[test]
    fn test_parse_algorithm_rs512() {
        let alg = parse_algorithm(&["RS512".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::RS512);
    }

    #[test]
    fn test_parse_algorithm_es256() {
        let alg = parse_algorithm(&["ES256".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::ES256);
    }

    #[test]
    fn test_parse_algorithm_es384() {
        let alg = parse_algorithm(&["ES384".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::ES384);
    }

    #[test]
    fn test_parse_algorithm_ps256() {
        let alg = parse_algorithm(&["PS256".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::PS256);
    }

    #[test]
    fn test_parse_algorithm_eddsa() {
        let alg = parse_algorithm(&["EdDSA".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::EdDSA);
    }

    #[test]
    fn test_parse_algorithm_unsupported() {
        let result = parse_algorithm(&["HS256".to_string()]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unsupported algorithm"));
    }

    #[test]
    fn test_parse_algorithm_empty_defaults_to_rs256() {
        let alg = parse_algorithm(&[]).unwrap();
        assert_eq!(alg, Algorithm::RS256);
    }

    #[test]
    fn test_build_decoding_key_rsa() {
        // Use real base64url-encoded RSA components (small test values)
        let jwk = Jwk {
            kid: Some("rsa-key-1".to_string()),
            kty: "RSA".to_string(),
            // These are base64url-encoded values for a minimal RSA public key
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_decoding_key_rsa_missing_n() {
        let jwk = Jwk {
            kid: None,
            kty: "RSA".to_string(),
            n: None,
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'n'"));
    }

    #[test]
    fn test_build_decoding_key_rsa_missing_e() {
        let jwk = Jwk {
            kid: None,
            kty: "RSA".to_string(),
            n: Some("abc".to_string()),
            e: None,
            x: None,
            y: None,
            crv: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'e'"));
    }

    #[test]
    fn test_build_decoding_key_ec_missing_x() {
        let jwk = Jwk {
            kid: None,
            kty: "EC".to_string(),
            n: None,
            e: None,
            x: None,
            y: Some("y-val".to_string()),
            crv: Some("P-256".to_string()),
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'x'"));
    }

    #[test]
    fn test_build_decoding_key_ec_missing_y() {
        let jwk = Jwk {
            kid: None,
            kty: "EC".to_string(),
            n: None,
            e: None,
            x: Some("x-val".to_string()),
            y: None,
            crv: Some("P-256".to_string()),
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'y'"));
    }

    #[test]
    fn test_build_decoding_key_okp_missing_x() {
        let jwk = Jwk {
            kid: None,
            kty: "OKP".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: Some("Ed25519".to_string()),
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'x'"));
    }

    #[test]
    fn test_build_decoding_key_unsupported_kty() {
        let jwk = Jwk {
            kid: None,
            kty: "oct".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("Unsupported key type")
        );
    }

    #[test]
    fn test_find_matching_key_by_kid() {
        let keys = vec![
            Jwk {
                kid: Some("key-1".to_string()),
                kty: "RSA".to_string(),
                n: Some("n1".to_string()),
                e: Some("e1".to_string()),
                x: None,
                y: None,
                crv: None,
            },
            Jwk {
                kid: Some("key-2".to_string()),
                kty: "RSA".to_string(),
                n: Some("n2".to_string()),
                e: Some("e2".to_string()),
                x: None,
                y: None,
                crv: None,
            },
        ];
        let found = find_matching_key(&keys, Some("key-2")).unwrap();
        assert_eq!(found.kid.as_deref(), Some("key-2"));
        assert_eq!(found.n.as_deref(), Some("n2"));
    }

    #[test]
    fn test_find_matching_key_no_kid_returns_first() {
        let keys = vec![Jwk {
            kid: Some("only".to_string()),
            kty: "RSA".to_string(),
            n: Some("n".to_string()),
            e: Some("e".to_string()),
            x: None,
            y: None,
            crv: None,
        }];
        let found = find_matching_key(&keys, None).unwrap();
        assert_eq!(found.kid.as_deref(), Some("only"));
    }

    #[test]
    fn test_find_matching_key_empty_keys() {
        let keys: Vec<Jwk> = vec![];
        let result = find_matching_key(&keys, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_matching_key_kid_not_found() {
        let keys = vec![Jwk {
            kid: Some("key-1".to_string()),
            kty: "RSA".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
        }];
        let result = find_matching_key(&keys, Some("nonexistent"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No key found"));
    }

    #[test]
    fn test_jwks_manager_new_does_not_panic() {
        let _manager = JwksManager::new();
    }

    #[test]
    fn test_jwks_manager_default() {
        let _manager = JwksManager::default();
    }

    #[tokio::test]
    async fn test_validate_jwt_rejects_empty_audience() {
        let mgr = JwksManager::new();
        let err = mgr
            .validate_jwt("token", "https://x/jwks", "https://issuer", &[], &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("audience"));
    }

    #[tokio::test]
    async fn test_validate_jwt_rejects_empty_issuer() {
        let mgr = JwksManager::new();
        let err = mgr
            .validate_jwt("token", "https://x/jwks", "", &["aud".to_string()], &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("issuer"));
    }
}

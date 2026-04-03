use anyhow::{Context, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::debug;

const JWKS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

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
    pub async fn validate_jwt(
        &self,
        token: &str,
        jwks_url: &str,
        audience: &[String],
        algorithms: &[String],
    ) -> Result<HashMap<String, serde_json::Value>> {
        let header = decode_header(token).context("Invalid JWT header")?;

        let keys = self.get_keys(jwks_url).await?;

        let kid = header.kid.as_deref();
        let key = find_matching_key(&keys, kid)?;

        let mut validation = Validation::new(parse_algorithm(algorithms)?);
        if audience.is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(audience);
        }

        let decoding_key = build_decoding_key(key)?;
        let token_data =
            decode::<HashMap<String, serde_json::Value>>(token, &decoding_key, &validation)
                .context("JWT validation failed")?;

        Ok(token_data.claims)
    }

    async fn get_keys(&self, jwks_url: &str) -> Result<Vec<Jwk>> {
        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(jwks_url) {
                if cached.fetched_at.elapsed() < JWKS_CACHE_TTL {
                    return Ok(cached.keys.clone());
                }
            }
        }

        // Fetch
        debug!(url = %jwks_url, "Fetching JWKS");
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
        kty => anyhow::bail!("Unsupported key type: {kty}"),
    }
}

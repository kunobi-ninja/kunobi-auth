use serde::{Deserialize, Serialize};

/// Authentication method configuration.
/// Exactly one field should be set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthMethod {
    /// OIDC provider authentication.
    #[serde(default)]
    pub oidc: Option<OidcAuth>,
    /// Static bearer token authentication.
    #[serde(default)]
    pub token: Option<TokenAuth>,
    /// Kubernetes ServiceAccount authentication.
    #[serde(default)]
    pub service_account: Option<ServiceAccountAuth>,
}

/// OIDC provider configuration for JWT validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcAuth {
    /// OIDC issuer URL (must match `iss` claim).
    pub issuer: String,
    /// JWKS URL for key fetching. Defaults to `{issuer}/.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Expected audience (`aud` claim). Empty = skip validation.
    #[serde(default)]
    pub audience: Vec<String>,
    /// Expected authorized parties (`azp` claim). Empty = skip validation.
    #[serde(default)]
    pub authorized_parties: Vec<String>,
    /// Allowed JWT signing algorithms. Defaults to `["RS256"]`.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    /// OAuth2 client ID for CLI login flow.
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Static bearer token authentication via a named secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAuth {
    /// Reference to the secret containing the token.
    pub secret_ref: String,
}

/// Kubernetes ServiceAccount-based authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountAuth {
    /// ServiceAccount name.
    pub name: String,
    /// ServiceAccount namespace.
    pub namespace: String,
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".to_string()]
}

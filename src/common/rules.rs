use serde::{Deserialize, Serialize};

/// Authentication method configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthMethod {
    #[serde(default)]
    pub oidc: Option<OidcAuth>,
    #[serde(default)]
    pub token: Option<TokenAuth>,
    #[serde(default)]
    pub service_account: Option<ServiceAccountAuth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcAuth {
    pub issuer: String,
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default)]
    pub audience: Vec<String>,
    #[serde(default)]
    pub authorized_parties: Vec<String>,
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAuth {
    pub secret_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountAuth {
    pub name: String,
    pub namespace: String,
}

/// Authorization rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessRule {
    #[serde(default, rename = "match")]
    pub match_clause: Option<ClaimMatch>,
    pub resources: Vec<String>,
    pub max_ttl: String,
    pub max_concurrent: u32,
    #[serde(default = "default_max_extensions")]
    pub max_extensions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimMatch {
    pub claim: String,
    pub value: String,
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".to_string()]
}

fn default_max_extensions() -> u32 {
    2
}

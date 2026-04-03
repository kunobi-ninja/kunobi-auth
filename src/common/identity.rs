use serde::{Deserialize, Serialize};

/// Validated identity extracted from a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthIdentity {
    /// Provider identifier (e.g. policy name).
    pub provider: String,
    /// Identity string (from template interpolation).
    pub identity: String,
    /// Method used to authenticate.
    pub method: String,
    /// Resolved authorization -- what this identity can access.
    pub authorization: ResolvedAuth,
}

/// What an authenticated identity is allowed to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAuth {
    /// Resource patterns this identity can access.
    pub allowed_resources: Vec<String>,
    /// Maximum TTL.
    pub max_ttl: chrono::Duration,
    /// Maximum concurrent active requests.
    pub max_concurrent: u32,
    /// Maximum extensions.
    pub max_extensions: u32,
}

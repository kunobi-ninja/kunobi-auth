use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Validated identity extracted from a request.
///
/// Contains the authenticated caller's identity and raw claims.
/// AuthZ decisions are left to the consuming service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthIdentity {
    /// Provider identifier (e.g. access policy name).
    pub provider: String,
    /// Identity string (from template interpolation).
    pub identity: String,
    /// Method used to authenticate ("oidc", "token").
    pub method: String,
    /// Raw claims from the JWT (OIDC) or empty for token auth.
    /// Services use these for their own authorization decisions.
    #[serde(default)]
    pub claims: HashMap<String, serde_json::Value>,
}

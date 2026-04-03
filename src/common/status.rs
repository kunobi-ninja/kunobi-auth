use serde::{Deserialize, Serialize};

/// Response for GET /v1/status.
/// The `app` field is generic -- each service adds its own data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse<T = serde_json::Value> {
    pub version: String,
    pub auth: AuthStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthStatus {
    pub methods: Vec<AuthMethodInfo>,
    #[serde(default)]
    pub sessions: Vec<Session>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthMethodInfo {
    #[serde(rename = "type")]
    pub method_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub method: String,
    pub identity: String,
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

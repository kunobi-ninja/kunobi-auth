use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Internal auth error: {0}")]
    Internal(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AuthError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AuthError::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            AuthError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

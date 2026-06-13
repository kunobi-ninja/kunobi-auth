#[cfg(feature = "server")]
use axum::http::StatusCode;
#[cfg(feature = "server")]
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    /// A server-side fault (500-class). `message` is a static, redaction-safe
    /// summary surfaced in logs and Display; `source` carries the underlying
    /// cause for server-side diagnostics via [`std::error::Error::source`] and
    /// is NEVER serialized into the HTTP response body. Construct with
    /// [`AuthError::internal`] / [`AuthError::internal_with_source`] rather than
    /// the struct literal.
    #[error("Internal auth error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
}

impl AuthError {
    /// An [`Internal`](AuthError::Internal) error with no underlying cause.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
            source: None,
        }
    }

    /// An [`Internal`](AuthError::Internal) error carrying its underlying cause.
    ///
    /// `message` should be a static, redaction-safe summary (it is the only
    /// part surfaced to the client); the rich `source` detail is kept for
    /// server-side logs / [`Error::source`](std::error::Error::source) and
    /// never leaks into the response body. Accepts anything convertible into a
    /// boxed error, including [`anyhow::Error`].
    pub fn internal_with_source(
        message: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self::Internal {
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// The RFC 6750 `error` code for a `WWW-Authenticate: Bearer` challenge,
    /// or `None` for variants that do not carry a bearer challenge.
    ///
    /// Additive accessor — it does not change the variant shapes:
    /// - [`Unauthorized`](AuthError::Unauthorized) → `Some("invalid_token")`
    /// - [`Forbidden`](AuthError::Forbidden) → `Some("insufficient_scope")`
    /// - [`RateLimited`](AuthError::RateLimited) / [`Internal`](AuthError::Internal) → `None`
    pub fn www_authenticate_error_code(&self) -> Option<&'static str> {
        match self {
            AuthError::Unauthorized(_) => Some("invalid_token"),
            AuthError::Forbidden(_) => Some("insufficient_scope"),
            AuthError::RateLimited(_) | AuthError::Internal { .. } => None,
        }
    }
}

/// Build a `WWW-Authenticate: Bearer ...` header value with an RFC 6750
/// `error` / `error_description`.
///
/// `error_description` is emitted as an RFC 7235 `quoted-string`, with `"` and
/// `\` backslash-escaped and bare CR/LF dropped (header-injection safe). Kept
/// deliberately small and plain — the MCP challenge builder
/// (`McpWwwAuthenticate`) adds metadata-specific params we don't want here.
#[cfg(feature = "server")]
fn bearer_challenge(error: &str, error_description: &str) -> String {
    let mut value = String::from("Bearer error=\"");
    value.push_str(error);
    value.push_str("\", error_description=\"");
    push_quoted_string(&mut value, error_description);
    value.push('"');
    value
}

/// Append `text` into an RFC 7235 `quoted-string` body (without the surrounding
/// quotes), escaping `"` and `\` and dropping bare CR/LF to prevent header
/// injection.
#[cfg(feature = "server")]
fn push_quoted_string(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '\r' | '\n' => {}
            _ => out.push(ch),
        }
    }
}

#[cfg(feature = "server")]
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // `challenge` is the optional `WWW-Authenticate: Bearer ...` value.
        // Built only for the bearer-relevant variants (401/403); RateLimited
        // (429) and Internal (500) carry no challenge. Internal additionally
        // keeps its body redacted and its existing error log.
        let (status, message, challenge) = match &self {
            AuthError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                msg.clone(),
                Some(bearer_challenge("invalid_token", msg)),
            ),
            AuthError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                msg.clone(),
                Some(bearer_challenge("insufficient_scope", msg)),
            ),
            AuthError::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone(), None),
            AuthError::Internal { message, source } => {
                // Log the static summary plus the underlying cause (server-side
                // only); the body below stays the redacted static string.
                match source {
                    Some(cause) => {
                        tracing::error!(error = %message, cause = %cause, "internal auth error")
                    }
                    None => tracing::error!(error = %message, "internal auth error"),
                }
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal auth error".to_string(),
                    None,
                )
            }
        };

        let body = serde_json::json!({ "error": message });
        let mut response = (status, axum::Json(body)).into_response();
        if let Some(challenge) = challenge {
            // A malformed value can't be set as a header; skip rather than
            // panic. `bearer_challenge` already strips CR/LF, so this is
            // effectively infallible for our inputs.
            if let Ok(value) = axum::http::HeaderValue::from_str(&challenge) {
                response
                    .headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, value);
            }
        }
        response
    }
}

#[cfg(all(test, feature = "server"))]
mod response_tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;

    async fn response_parts(err: AuthError) -> (StatusCode, String) {
        let response = err.into_response();
        let status = response.status();
        let body = Body::new(response.into_body())
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        (status, text)
    }

    /// Status, body text, and the `WWW-Authenticate` header (if any).
    async fn response_parts_with_challenge(err: AuthError) -> (StatusCode, String, Option<String>) {
        let response = err.into_response();
        let status = response.status();
        let challenge = response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().unwrap().to_string());
        let body = Body::new(response.into_body())
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        (status, text, challenge)
    }

    #[tokio::test]
    async fn test_unauthorized_produces_401() {
        let (status, _) = response_parts(AuthError::Unauthorized("bad token".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_forbidden_produces_403() {
        let (status, _) = response_parts(AuthError::Forbidden("no access".into())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_rate_limited_produces_429() {
        let (status, _) = response_parts(AuthError::RateLimited("slow down".into())).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_internal_produces_500() {
        let (status, _) = response_parts(AuthError::internal("boom")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_error_message_in_body() {
        let (_, body) = response_parts(AuthError::Unauthorized("invalid jwt".into())).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["error"], "invalid jwt");
    }

    #[tokio::test]
    async fn test_internal_error_body_is_redacted() {
        let (_, body) =
            response_parts(AuthError::internal("db password=secret backend detail")).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["error"], "internal auth error");
        assert!(!body.contains("secret"));
        assert!(!body.contains("backend detail"));
    }

    #[tokio::test]
    async fn test_internal_with_source_redacts_both_message_and_cause() {
        // Even with a cause attached, neither the static message nor the
        // underlying source detail may reach the response body.
        let cause = std::io::Error::other("secret cause: db password=hunter2");
        let (status, body, challenge) = response_parts_with_challenge(
            AuthError::internal_with_source("backend exploded", cause),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(challenge.is_none(), "Internal must not carry a challenge");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["error"], "internal auth error");
        assert!(!body.contains("secret cause"));
        assert!(!body.contains("hunter2"));
        assert!(!body.contains("backend exploded"));
    }

    // ── WWW-Authenticate challenge ────────────────────────────────────────

    #[tokio::test]
    async fn test_unauthorized_sets_invalid_token_challenge() {
        let (status, body, challenge) =
            response_parts_with_challenge(AuthError::Unauthorized("token expired".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let challenge = challenge.expect("Unauthorized must carry a WWW-Authenticate header");
        assert_eq!(
            challenge,
            "Bearer error=\"invalid_token\", error_description=\"token expired\""
        );
        // Body shape is unchanged.
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["error"], "token expired");
    }

    #[tokio::test]
    async fn test_forbidden_sets_insufficient_scope_challenge() {
        let (status, body, challenge) = response_parts_with_challenge(AuthError::Forbidden(
            "scope crawl:write required".into(),
        ))
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let challenge = challenge.expect("Forbidden must carry a WWW-Authenticate header");
        assert!(challenge.starts_with("Bearer error=\"insufficient_scope\""));
        assert!(challenge.contains("error_description=\"scope crawl:write required\""));
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["error"], "scope crawl:write required");
    }

    #[tokio::test]
    async fn test_internal_has_no_challenge_and_redacts_body() {
        // The redaction guarantee must still hold AND no challenge must leak.
        let (status, body, challenge) =
            response_parts_with_challenge(AuthError::internal("db password=secret backend detail"))
                .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(challenge.is_none(), "Internal must not carry a challenge");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["error"], "internal auth error");
        assert!(!body.contains("secret"));
        assert!(!body.contains("backend detail"));
    }

    #[tokio::test]
    async fn test_rate_limited_has_no_challenge() {
        let (status, _, challenge) =
            response_parts_with_challenge(AuthError::RateLimited("slow down".into())).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            challenge.is_none(),
            "RateLimited must not carry a challenge"
        );
    }

    #[tokio::test]
    async fn test_challenge_escapes_quotes_in_description() {
        // A `"` in the message must be backslash-escaped in the header so the
        // quoted-string stays well-formed.
        let (_, _, challenge) =
            response_parts_with_challenge(AuthError::Unauthorized("bad \"token\"".into())).await;
        let challenge = challenge.unwrap();
        assert_eq!(
            challenge,
            "Bearer error=\"invalid_token\", error_description=\"bad \\\"token\\\"\""
        );
    }

    #[test]
    fn test_quoted_string_escapes_backslash_and_drops_crlf() {
        let mut out = String::new();
        push_quoted_string(&mut out, "a\\b\"c\r\nd");
        // backslash -> \\, quote -> \", CR/LF dropped.
        assert_eq!(out, "a\\\\b\\\"cd");
    }

    #[test]
    fn test_www_authenticate_error_code() {
        assert_eq!(
            AuthError::Unauthorized("x".into()).www_authenticate_error_code(),
            Some("invalid_token")
        );
        assert_eq!(
            AuthError::Forbidden("x".into()).www_authenticate_error_code(),
            Some("insufficient_scope")
        );
        assert_eq!(
            AuthError::RateLimited("x".into()).www_authenticate_error_code(),
            None
        );
        assert_eq!(AuthError::internal("x").www_authenticate_error_code(), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_messages() {
        assert_eq!(
            AuthError::Unauthorized("x".into()).to_string(),
            "Unauthorized: x"
        );
        assert_eq!(AuthError::Forbidden("y".into()).to_string(), "Forbidden: y");
        assert_eq!(
            AuthError::RateLimited("z".into()).to_string(),
            "Rate limited: z"
        );
        assert_eq!(
            AuthError::internal("w").to_string(),
            "Internal auth error: w"
        );
    }

    #[test]
    fn internal_source_chain_is_preserved_and_display_stays_static() {
        use std::error::Error;

        // No cause: Display is the static message, source() is None.
        let bare = AuthError::internal("clock skew");
        assert_eq!(bare.to_string(), "Internal auth error: clock skew");
        assert!(bare.source().is_none());

        // With a cause: Display is unchanged (static), but source() exposes the
        // underlying error for server-side diagnostics.
        let with_cause = AuthError::internal_with_source(
            "clock skew",
            std::io::Error::other("system time before UNIX epoch"),
        );
        assert_eq!(with_cause.to_string(), "Internal auth error: clock skew");
        let source = with_cause.source().expect("source must be exposed");
        assert!(source.to_string().contains("UNIX epoch"));
    }

    #[test]
    fn internal_with_source_accepts_anyhow_error() {
        use std::error::Error;
        // The classify path boxes an `anyhow::Error`; make sure that compiles
        // and round-trips through source().
        let err: anyhow::Error = anyhow::anyhow!("root").context("ctx");
        let auth = AuthError::internal_with_source("JWKS fetch/transport failure", err);
        assert_eq!(
            auth.to_string(),
            "Internal auth error: JWKS fetch/transport failure"
        );
        assert!(auth.source().is_some());
    }
}

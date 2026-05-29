//! MCP server authentication helpers.
//!
//! These helpers keep Model Context Protocol specifics at the edge:
//! protected-resource metadata, `WWW-Authenticate` challenges, and a required
//! bearer auth layer. Token validation still delegates to the normal
//! [`AuthnProvider`] path.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, Uri, header};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower::{Layer, Service};

use crate::common::AuthError;
use crate::server::middleware::AuthnProvider;

/// Default well-known path for OAuth Protected Resource Metadata.
pub const OAUTH_PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";

/// OAuth Protected Resource Metadata for an MCP resource server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// Canonical MCP resource URI. This is the resource/audience clients ask
    /// the authorization server to issue tokens for.
    pub resource: String,
    /// Authorization servers that can issue access tokens for this resource.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    /// Scopes the MCP resource server understands.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    /// Supported bearer-token presentation methods. MCP HTTP endpoints should
    /// use the `Authorization` header.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bearer_methods_supported: Vec<String>,
    /// Human-readable resource name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    /// URL for resource documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,
    /// JWT signing algorithms accepted by the resource server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_signing_alg_values_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    pub fn new<I, S>(resource: impl Into<String>, authorization_servers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            resource: resource.into(),
            authorization_servers: authorization_servers.into_iter().map(Into::into).collect(),
            scopes_supported: Vec::new(),
            bearer_methods_supported: vec!["header".into()],
            resource_name: None,
            resource_documentation: None,
            resource_signing_alg_values_supported: Vec::new(),
        }
    }

    pub fn scopes_supported<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes_supported = scopes.into_iter().map(Into::into).collect();
        self
    }

    pub fn resource_name(mut self, name: impl Into<String>) -> Self {
        self.resource_name = Some(name.into());
        self
    }

    pub fn resource_documentation(mut self, url: impl Into<String>) -> Self {
        self.resource_documentation = Some(url.into());
        self
    }

    pub fn signing_algorithms<I, S>(mut self, algorithms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.resource_signing_alg_values_supported =
            algorithms.into_iter().map(Into::into).collect();
        self
    }
}

/// Configuration used by MCP auth middleware and well-known metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerAuthConfig {
    metadata: ProtectedResourceMetadata,
    metadata_url: String,
    metadata_path: String,
    realm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpServerAuthConfigError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} must be an absolute URI")]
    InvalidUri { field: &'static str },
}

impl McpServerAuthConfig {
    /// Build MCP server auth config.
    ///
    /// The metadata URL is derived from `metadata.resource` per RFC 9728 by
    /// inserting `/.well-known/oauth-protected-resource` between the host and
    /// path.
    pub fn new(metadata: ProtectedResourceMetadata) -> Result<Self, McpServerAuthConfigError> {
        let metadata_url = metadata_url_for_resource(&metadata.resource)?;
        Self::with_metadata_url(metadata, metadata_url)
    }

    /// Build MCP server auth config with an explicit metadata URL.
    ///
    /// Use this when the public URL differs from the resource URL, for example
    /// behind a reverse proxy.
    pub fn with_metadata_url(
        metadata: ProtectedResourceMetadata,
        metadata_url: impl Into<String>,
    ) -> Result<Self, McpServerAuthConfigError> {
        let metadata_url = metadata_url.into();
        let metadata_path = validate_metadata(&metadata, &metadata_url)?;
        Ok(Self {
            metadata,
            metadata_url,
            metadata_path,
            realm: None,
        })
    }

    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }

    pub fn metadata(&self) -> &ProtectedResourceMetadata {
        &self.metadata
    }

    pub fn metadata_url(&self) -> &str {
        &self.metadata_url
    }

    pub fn metadata_router(&self) -> Router {
        protected_resource_metadata_router_at(&self.metadata_path, self.metadata.clone())
    }

    pub fn layer<P>(&self, provider: P) -> McpAuthLayer<P> {
        McpAuthLayer::new(provider, self.challenge())
    }

    pub fn challenge(&self) -> McpWwwAuthenticate {
        McpWwwAuthenticate {
            metadata_url: Arc::from(self.metadata_url.clone()),
            realm: self.realm.clone().map(Arc::from),
        }
    }
}

fn validate_metadata(
    metadata: &ProtectedResourceMetadata,
    metadata_url: &str,
) -> Result<String, McpServerAuthConfigError> {
    require_absolute_uri("resource", &metadata.resource)?;
    let metadata_uri = require_absolute_uri("metadata_url", metadata_url)?;
    let metadata_path = metadata_uri.path().to_string();
    if !metadata_path.starts_with(OAUTH_PROTECTED_RESOURCE_PATH) {
        return Err(McpServerAuthConfigError::InvalidUri {
            field: "metadata_url",
        });
    }
    if metadata.authorization_servers.is_empty() {
        return Err(McpServerAuthConfigError::Empty {
            field: "authorization_servers",
        });
    }
    for server in &metadata.authorization_servers {
        require_absolute_uri("authorization_servers", server)?;
    }
    Ok(metadata_path)
}

fn require_absolute_uri(field: &'static str, value: &str) -> Result<Uri, McpServerAuthConfigError> {
    if value.trim().is_empty() {
        return Err(McpServerAuthConfigError::Empty { field });
    }
    let uri = value
        .parse::<Uri>()
        .map_err(|_| McpServerAuthConfigError::InvalidUri { field })?;
    if uri.scheme().is_none() || uri.authority().is_none() {
        return Err(McpServerAuthConfigError::InvalidUri { field });
    }
    Ok(uri)
}

/// Derive the OAuth Protected Resource Metadata URL for a resource identifier
/// using RFC 9728's well-known insertion rule.
pub fn metadata_url_for_resource(resource: &str) -> Result<String, McpServerAuthConfigError> {
    let uri = require_absolute_uri("resource", resource)?;
    let scheme = uri
        .scheme_str()
        .ok_or(McpServerAuthConfigError::InvalidUri { field: "resource" })?;
    let authority = uri
        .authority()
        .ok_or(McpServerAuthConfigError::InvalidUri { field: "resource" })?;
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("");

    let mut metadata_url = format!("{scheme}://{authority}{OAUTH_PROTECTED_RESOURCE_PATH}");
    if !path_and_query.is_empty() && path_and_query != "/" {
        metadata_url.push_str(path_and_query);
    }
    Ok(metadata_url)
}

/// Build a standalone router for `/.well-known/oauth-protected-resource`.
pub fn protected_resource_metadata_router(metadata: ProtectedResourceMetadata) -> Router {
    protected_resource_metadata_router_at(OAUTH_PROTECTED_RESOURCE_PATH, metadata)
}

/// Build a standalone router for a specific OAuth Protected Resource Metadata path.
pub fn protected_resource_metadata_router_at(
    path: &str,
    metadata: ProtectedResourceMetadata,
) -> Router {
    let metadata = Arc::new(metadata);
    Router::new().route(
        path,
        get({
            let metadata = metadata.clone();
            move || {
                let metadata = metadata.clone();
                async move { Json((*metadata).clone()) }
            }
        }),
    )
}

/// Builder for MCP `WWW-Authenticate` challenges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpWwwAuthenticate {
    metadata_url: Arc<str>,
    realm: Option<Arc<str>>,
}

impl McpWwwAuthenticate {
    pub fn new(metadata_url: impl Into<String>) -> Result<Self, McpServerAuthConfigError> {
        let metadata_url = metadata_url.into();
        require_absolute_uri("metadata_url", &metadata_url)?;
        Ok(Self {
            metadata_url: Arc::from(metadata_url),
            realm: None,
        })
    }

    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(Arc::from(realm.into()));
        self
    }

    pub fn header_value(&self, error: Option<&str>, error_description: Option<&str>) -> String {
        let mut value = "Bearer".to_string();
        let mut first = true;
        if let Some(realm) = &self.realm {
            push_auth_param(&mut value, &mut first, "realm", realm);
        }
        push_auth_param(
            &mut value,
            &mut first,
            "resource_metadata",
            &self.metadata_url,
        );
        if let Some(error) = error {
            push_auth_param(&mut value, &mut first, "error", error);
        }
        if let Some(error_description) = error_description {
            push_auth_param(
                &mut value,
                &mut first,
                "error_description",
                error_description,
            );
        }
        value
    }

    pub fn unauthorized_response(
        &self,
        error: Option<&str>,
        error_description: Option<&str>,
    ) -> Response<Body> {
        let body_error = error.unwrap_or("authorization_required");
        let mut response = (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": body_error })),
        )
            .into_response();
        if let Ok(value) =
            axum::http::HeaderValue::from_str(&self.header_value(error, error_description))
        {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

fn push_auth_param(value: &mut String, first: &mut bool, name: &str, param_value: &str) {
    if *first {
        value.push(' ');
        *first = false;
    } else {
        value.push_str(", ");
    }
    value.push_str(name);
    value.push_str("=\"");
    for ch in param_value.chars() {
        match ch {
            '"' | '\\' => {
                value.push('\\');
                value.push(ch);
            }
            '\r' | '\n' => {}
            _ => value.push(ch),
        }
    }
    value.push('"');
}

#[derive(Clone, Debug)]
pub struct McpAuthLayer<P> {
    provider: P,
    challenge: McpWwwAuthenticate,
}

impl<P> McpAuthLayer<P> {
    pub fn new(provider: P, challenge: McpWwwAuthenticate) -> Self {
        Self {
            provider,
            challenge,
        }
    }
}

impl<S, P> Layer<S> for McpAuthLayer<P>
where
    P: AuthnProvider,
{
    type Service = McpAuthService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        McpAuthService {
            inner,
            provider: self.provider.clone(),
            challenge: self.challenge.clone(),
        }
    }
}

#[derive(Clone)]
pub struct McpAuthService<S, P> {
    inner: S,
    provider: P,
    challenge: McpWwwAuthenticate,
}

impl<S, P> Service<Request<Body>> for McpAuthService<S, P>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    P: AuthnProvider,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let provider = self.provider.clone();
        let challenge = self.challenge.clone();

        Box::pin(async move {
            let Some(token) = extract_bearer(&req) else {
                return Ok(challenge.unauthorized_response(None, None));
            };

            match provider.authenticate(token).await {
                Ok(identity) => {
                    req.extensions_mut().insert(identity);
                    inner.call(req).await
                }
                Err(AuthError::Unauthorized(message)) => {
                    Ok(challenge.unauthorized_response(Some("invalid_token"), Some(&message)))
                }
                Err(error) => Ok(error.into_response()),
            }
        })
    }
}

fn extract_bearer<B>(req: &Request<B>) -> Option<&str> {
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    // `header.get(..7)` returns `None` when the header is shorter than 7 bytes
    // *or* when byte 7 isn't a UTF-8 char boundary -- so a header like
    // `Authorization: €€€` can never panic the way `header[..7]` would.
    let prefix = header.get(..7)?;
    if prefix.eq_ignore_ascii_case("Bearer ") {
        Some(&header[7..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::AuthIdentity;
    use axum::Extension;
    use axum::http::StatusCode;
    use axum::routing::get;
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use tower::ServiceExt;

    #[derive(Clone)]
    struct TestAuth;

    impl AuthnProvider for TestAuth {
        async fn authenticate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
            match token {
                "valid-token" => Ok(AuthIdentity {
                    provider: "test".into(),
                    identity: "user-1".into(),
                    method: "token".into(),
                    claims: HashMap::new(),
                }),
                "boom" => Err(AuthError::Internal("database down".into())),
                _ => Err(AuthError::Unauthorized("bad token".into())),
            }
        }
    }

    fn metadata() -> ProtectedResourceMetadata {
        ProtectedResourceMetadata::new(
            "https://crawl.example.com/mcp",
            ["https://auth.example.com"],
        )
        .scopes_supported(["crawl:read", "crawl:write"])
        .resource_name("omega-crawl")
    }

    fn config() -> McpServerAuthConfig {
        McpServerAuthConfig::new(metadata()).unwrap()
    }

    async fn body_text(response: Response<Body>) -> String {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[test]
    fn metadata_serializes_expected_fields() {
        let json = serde_json::to_value(metadata()).unwrap();
        assert_eq!(json["resource"], "https://crawl.example.com/mcp");
        assert_eq!(json["authorization_servers"][0], "https://auth.example.com");
        assert_eq!(json["bearer_methods_supported"][0], "header");
        assert_eq!(json["scopes_supported"][0], "crawl:read");
        assert_eq!(json["resource_name"], "omega-crawl");
        assert!(json.get("resource_documentation").is_none());
    }

    #[test]
    fn config_rejects_missing_authorization_servers() {
        let metadata =
            ProtectedResourceMetadata::new("https://crawl.example.com/mcp", Vec::<String>::new());
        let err = McpServerAuthConfig::new(metadata).unwrap_err();
        assert_eq!(
            err,
            McpServerAuthConfigError::Empty {
                field: "authorization_servers"
            }
        );
    }

    #[test]
    fn metadata_url_for_resource_inserts_well_known_before_path() {
        assert_eq!(
            metadata_url_for_resource("https://crawl.example.com/mcp").unwrap(),
            "https://crawl.example.com/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            metadata_url_for_resource("https://crawl.example.com").unwrap(),
            "https://crawl.example.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn challenge_quotes_and_escapes_params() {
        let challenge = McpWwwAuthenticate::new(
            "https://crawl.example.com/.well-known/oauth-protected-resource",
        )
        .unwrap()
        .realm("crawl");
        assert_eq!(
            challenge.header_value(Some("invalid_token"), Some("bad \"token\"")),
            "Bearer realm=\"crawl\", resource_metadata=\"https://crawl.example.com/.well-known/oauth-protected-resource\", error=\"invalid_token\", error_description=\"bad \\\"token\\\"\""
        );
    }

    #[tokio::test]
    async fn metadata_router_serves_well_known_json() {
        let app = config().metadata_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&body_text(response).await).unwrap();
        assert_eq!(body["resource"], "https://crawl.example.com/mcp");
    }

    #[tokio::test]
    async fn mcp_auth_layer_rejects_missing_token_with_challenge() {
        async fn handler() -> &'static str {
            "ok"
        }

        let app = Router::new()
            .route("/mcp", get(handler))
            .layer(config().layer(TestAuth));

        let response = app
            .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let header = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            header,
            "Bearer resource_metadata=\"https://crawl.example.com/.well-known/oauth-protected-resource/mcp\""
        );
    }

    #[tokio::test]
    async fn mcp_auth_layer_rejects_bad_token_with_invalid_token() {
        async fn handler() -> &'static str {
            "ok"
        }

        let app = Router::new()
            .route("/mcp", get(handler))
            .layer(config().layer(TestAuth));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let header = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(header.contains("error=\"invalid_token\""));
        assert!(header.contains("error_description=\"bad token\""));
    }

    #[tokio::test]
    async fn mcp_auth_layer_inserts_identity_for_valid_token() {
        async fn handler(Extension(identity): Extension<AuthIdentity>) -> String {
            identity.identity
        }

        let app = Router::new()
            .route("/mcp", get(handler))
            .layer(config().layer(TestAuth));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, "bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "user-1");
    }

    #[tokio::test]
    async fn mcp_auth_layer_handles_multibyte_authorization_without_panicking() {
        // A header whose first bytes are multibyte UTF-8 used to panic
        // `&header[..7]` on a non-char-boundary. It must now be treated as a
        // missing/invalid scheme and answered with a 401 challenge.
        async fn handler() -> &'static str {
            "ok"
        }

        let app = Router::new()
            .route("/mcp", get(handler))
            .layer(config().layer(TestAuth));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, "€€€")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mcp_auth_layer_preserves_internal_errors() {
        async fn handler() -> &'static str {
            "ok"
        }

        let app = Router::new()
            .route("/mcp", get(handler))
            .layer(config().layer(TestAuth));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, "Bearer boom")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    }
}

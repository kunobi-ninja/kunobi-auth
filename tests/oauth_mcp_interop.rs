//! Check the wire contract between the MCP server helpers and OAuth client.
#![cfg(all(feature = "oauth", feature = "mcp-server"))]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use kunobi_auth::oauth::discovery::{
    ProtectedResourceMetadata as ClientMetadata, parse_www_authenticate_resource_metadata,
    protected_resource_metadata_urls,
};
use kunobi_auth::server::mcp::{McpServerAuthConfig, ProtectedResourceMetadata};
use tower::ServiceExt;
use url::Url;

#[tokio::test]
async fn oauth_client_reads_mcp_server_challenge_and_metadata() {
    let resource = "https://api.example.com/team/mcp";
    let issuer = "https://auth.example.com/tenant";
    let minimal = ProtectedResourceMetadata::new(resource, [issuer]);
    let detailed = minimal
        .clone()
        .scopes_supported(["tools:read", "tools:write"])
        .resource_name("Example MCP")
        .resource_documentation("https://api.example.com/docs")
        .signing_algorithms(["RS256"]);

    for metadata in [minimal, detailed] {
        let config = McpServerAuthConfig::new(metadata.clone()).unwrap();
        let header = config
            .challenge()
            .header_value(Some("invalid_token"), Some("Grant expired"));
        let metadata_url = parse_www_authenticate_resource_metadata(&header).unwrap();
        assert_eq!(metadata_url.as_str(), config.metadata_url());
        assert_eq!(
            protected_resource_metadata_urls(&Url::parse(resource).unwrap())[0],
            metadata_url
        );

        let response = config
            .metadata_router()
            .oneshot(
                Request::builder()
                    .uri(metadata_url.path())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let client: ClientMetadata = serde_json::from_slice(&body).unwrap();
        assert_eq!(client.resource, resource);
        assert_eq!(client.authorization_servers, [issuer]);
        assert_eq!(client.scopes_supported, metadata.scopes_supported);
    }
}

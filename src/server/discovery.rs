//! Server side of Kunobi auth discovery.
//!
//! Serves the `GET {endpoint}/.well-known/kunobi-auth` document a client reads
//! to bootstrap OIDC trust (issuer + client_id [+ audience]). This closes the
//! discover/serve asymmetry: clients parse the document via
//! [`client::discover`](crate::client::discover), and this router publishes the
//! exact same wire shape ([`KunobiAuthDiscovery`]) so the two can never drift.
//!
//! Mirrors the MCP protected-resource-metadata router
//! ([`protected_resource_metadata_router`](crate::server::protected_resource_metadata_router)).

use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};

use crate::common::KunobiAuthDiscovery;

/// Default well-known path for the Kunobi auth-discovery document.
pub const KUNOBI_AUTH_DISCOVERY_PATH: &str = "/.well-known/kunobi-auth";

/// Build a standalone router that serves the Kunobi auth-discovery document at
/// the default [`KUNOBI_AUTH_DISCOVERY_PATH`].
pub fn kunobi_auth_discovery_router(metadata: KunobiAuthDiscovery) -> Router {
    kunobi_auth_discovery_router_at(KUNOBI_AUTH_DISCOVERY_PATH, metadata)
}

/// Build a standalone router that serves the Kunobi auth-discovery document at
/// a specific `path` (for example behind a reverse proxy that rewrites the
/// well-known prefix).
pub fn kunobi_auth_discovery_router_at(path: &str, metadata: KunobiAuthDiscovery) -> Router {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn metadata() -> KunobiAuthDiscovery {
        KunobiAuthDiscovery {
            issuer: "https://auth.example.com".into(),
            client_id: "kobe-cli".into(),
            audience: Some("https://api.example.com".into()),
        }
    }

    async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    #[tokio::test]
    async fn router_serves_well_known_document() {
        let app = kunobi_auth_discovery_router(metadata());
        let response = app
            .oneshot(
                Request::builder()
                    .uri(KUNOBI_AUTH_DISCOVERY_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: KunobiAuthDiscovery =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(body, metadata());
    }

    /// Cross-check: the served body must deserialize through the *same* type the
    /// client uses to parse discovery, proving both sides agree on the wire.
    /// The client (`client::discovery::discover`) does `response.json::<KunobiAuthDiscovery>()`,
    /// so deserializing the router's body into that type is the exact same path.
    #[tokio::test]
    async fn served_body_parses_through_client_deserialize() {
        let app = kunobi_auth_discovery_router(metadata());
        let response = app
            .oneshot(
                Request::builder()
                    .uri(KUNOBI_AUTH_DISCOVERY_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = body_bytes(response).await;
        // Same call shape the client's reqwest `.json()` uses.
        let parsed: KunobiAuthDiscovery = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.issuer, "https://auth.example.com");
        assert_eq!(parsed.client_id, "kobe-cli");
        assert_eq!(parsed.audience.as_deref(), Some("https://api.example.com"));
    }

    #[tokio::test]
    async fn router_omits_audience_when_none() {
        let app = kunobi_auth_discovery_router(KunobiAuthDiscovery {
            issuer: "https://auth.example.com".into(),
            client_id: "kobe-cli".into(),
            audience: None,
        });
        let response = app
            .oneshot(
                Request::builder()
                    .uri(KUNOBI_AUTH_DISCOVERY_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["issuer"], "https://auth.example.com");
        assert_eq!(json["clientId"], "kobe-cli");
        assert!(json.get("audience").is_none());
    }

    #[tokio::test]
    async fn router_at_serves_custom_path() {
        let app = kunobi_auth_discovery_router_at("/auth/discovery", metadata());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/discovery")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: KunobiAuthDiscovery =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(body, metadata());
    }
}

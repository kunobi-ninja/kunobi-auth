use anyhow::{Context, Result};
use axum::extract::Query;
use axum::response::Html;
use axum::routing::get;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, RedirectUrl, RefreshToken, Scope, TokenResponse,
};
use std::collections::HashMap;
use tokio::sync::oneshot;
use tracing::{info, warn};

use super::store::StoredToken;

fn build_http_client() -> Result<openidconnect::reqwest::Client> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")
}

/// Perform browser-based OIDC login with PKCE.
///
/// 1. Discovers the OIDC provider
/// 2. Generates a PKCE challenge + nonce
/// 3. Opens the browser to the authorization URL
/// 4. Starts a localhost server to receive the callback
/// 5. Exchanges the auth code for tokens
/// 6. Validates the ID token (signature, expiry, aud, iss, nonce)
/// 7. Returns the stored token
pub async fn browser_login(
    issuer: &str,
    client_id: &str,
    audience: Option<&str>,
    redirect_uri: &str,
) -> Result<StoredToken> {
    info!(issuer = %issuer, "Starting OIDC browser login");

    let http_client = build_http_client()?;

    let issuer_url = IssuerUrl::new(issuer.to_string()).context("Invalid issuer URL")?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .context("Failed to discover OIDC provider")?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        None, // public client (PKCE)
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).context("Invalid redirect URI")?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the nonce up-front so we can verify it on the returned ID token.
    let nonce = Nonce::new_random();
    let nonce_for_check = nonce.clone();

    let mut auth_request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            move || nonce.clone(),
        )
        .set_pkce_challenge(pkce_challenge)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("offline_access".to_string()));

    if let Some(aud) = audience {
        // Send both the RFC 8707 `resource` and the Auth0-style `audience`
        // parameter so different IdPs all bind a token to this audience.
        auth_request = auth_request
            .add_extra_param("audience", aud)
            .add_extra_param("resource", aud);
    }

    let (auth_url, csrf_token, _nonce) = auth_request.url();

    let (tx, rx) = oneshot::channel::<(String, String)>();
    let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let expected_state = csrf_token.secret().clone();
    let tx_clone = tx.clone();

    let app = axum::Router::new().route(
        "/callback",
        get(move |Query(params): Query<HashMap<String, String>>| {
            let tx = tx_clone.clone();
            let expected = expected_state.clone();
            async move {
                let code = params.get("code").cloned().unwrap_or_default();
                let state = params.get("state").cloned().unwrap_or_default();

                if state != expected {
                    return Html("<h1>Error</h1><p>Invalid state parameter.</p>".to_string());
                }

                if let Some(sender) = tx.lock().await.take() {
                    let _ = sender.send((code, state));
                }

                Html(
                    "<h1>Authenticated!</h1><p>You can close this tab.</p>\
                     <script>window.close()</script>"
                        .to_string(),
                )
            }
        }),
    );

    let port: u16 = redirect_uri
        .split(':')
        .next_back()
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(8329);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .with_context(|| {
            format!(
                "Failed to bind to port {port} (already in use?). Adjust ServiceConfig.redirect_uri or free the port."
            )
        })?;

    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    info!(url = %auth_url, "Opening browser for authentication");
    open::that(auth_url.to_string()).context("Failed to open browser")?;

    println!("Waiting for authentication in browser...");

    let (code, _state) = tokio::time::timeout(std::time::Duration::from_secs(120), rx)
        .await
        .context("Login timed out after 120 seconds")?
        .context("Callback channel closed")?;

    server.abort();

    info!("Exchanging authorization code for tokens");
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
        .context("Token exchange failed")?;

    let id_token = token_response
        .id_token()
        .context("OIDC token response did not contain an id_token")?;

    let claims = id_token
        .claims(&client.id_token_verifier(), &nonce_for_check)
        .context("ID token validation failed (signature/expiry/aud/iss/nonce)")?;

    let claim_issuer = claims.issuer().to_string();
    if claim_issuer != issuer {
        warn!(
            expected = %issuer,
            actual = %claim_issuer,
            "ID token issuer differs from configured issuer (using validated claim)"
        );
    }

    let id_token_str = id_token.to_string();
    let refresh_token = token_response.refresh_token().map(|t| t.secret().clone());
    let expires_at = token_response
        .expires_in()
        .map(|d| chrono::Utc::now().timestamp() + d.as_secs() as i64);

    Ok(StoredToken {
        id_token: id_token_str,
        refresh_token,
        expires_at,
        issuer: claim_issuer,
    })
}

/// Refresh an OIDC session using the stored refresh token.
pub async fn refresh(
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    refresh_token: &str,
) -> Result<StoredToken> {
    info!(issuer = %issuer, "Refreshing OIDC token");

    let http_client = build_http_client()?;

    let issuer_url = IssuerUrl::new(issuer.to_string()).context("Invalid issuer URL")?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .context("Failed to discover OIDC provider")?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        None,
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).context("Invalid redirect URI")?);

    let response = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))?
        .request_async(&http_client)
        .await
        .context("Refresh-token exchange failed")?;

    let id_token = response
        .id_token()
        .context("Refresh-token response did not contain an id_token")?;

    // Refresh responses don't carry a nonce; signature/expiry/aud/iss still
    // validated.
    let claims = id_token
        .claims(&client.id_token_verifier(), |_: Option<&Nonce>| Ok(()))
        .context("Refreshed ID token validation failed")?;

    let claim_issuer = claims.issuer().to_string();
    let id_token_str = id_token.to_string();
    let new_refresh = response.refresh_token().map(|t| t.secret().clone());
    let expires_at = response
        .expires_in()
        .map(|d| chrono::Utc::now().timestamp() + d.as_secs() as i64);

    Ok(StoredToken {
        id_token: id_token_str,
        refresh_token: new_refresh.or_else(|| Some(refresh_token.to_string())),
        expires_at,
        issuer: claim_issuer,
    })
}

use super::config::ServiceConfig;
use crate::common::KunobiAuthDiscovery;
use anyhow::Context;
use std::net::IpAddr;
use std::time::Duration;

/// Fetch auth configuration from a Kunobi service.
///
/// Calls `GET {endpoint}/.well-known/kunobi-auth` to discover the OIDC
/// provider and client configuration.
///
/// This bootstraps trust (issuer + client_id), so the transport is hardened:
/// `https` is required outside loopback, and redirects are disabled to prevent
/// a MITM from silently relocating discovery to an attacker-controlled origin.
pub async fn discover(endpoint: &str) -> anyhow::Result<ServiceConfig> {
    let endpoint = endpoint.trim_end_matches('/');
    let url = format!("{endpoint}/.well-known/kunobi-auth");

    enforce_secure_transport(&url)?;

    tracing::info!(url = %url, "Discovering auth configuration");

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build discovery HTTP client")?;
    let response = http.get(&url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!(
            "Auth discovery failed (HTTP {}): {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    let discovery: KunobiAuthDiscovery = response.json().await?;

    Ok(ServiceConfig {
        endpoint: endpoint.to_string(),
        issuer: discovery.issuer,
        client_id: discovery.client_id,
        audience: discovery.audience,
        redirect_uri: "http://localhost:8329/callback".to_string(),
    })
}

/// Require `https` for the discovery URL, allowing plaintext `http` only for
/// loopback hosts (local development / tests).
fn enforce_secure_transport(url: &str) -> anyhow::Result<()> {
    let parsed =
        reqwest::Url::parse(url).with_context(|| format!("discovery URL is invalid: {url}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_url(&parsed) => Ok(()),
        "http" => anyhow::bail!("discovery endpoint must use https outside loopback hosts: {url}"),
        scheme => anyhow::bail!("discovery endpoint must use https, got {scheme}: {url}"),
    }
}

fn is_loopback_url(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plaintext_remote_discovery() {
        let err = enforce_secure_transport("http://service.example.com/.well-known/kunobi-auth")
            .unwrap_err();
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn accepts_https_and_loopback_http() {
        enforce_secure_transport("https://service.example.com/.well-known/kunobi-auth").unwrap();
        enforce_secure_transport("http://127.0.0.1:8080/.well-known/kunobi-auth").unwrap();
        enforce_secure_transport("http://localhost/.well-known/kunobi-auth").unwrap();
        enforce_secure_transport("http://[::1]:9000/.well-known/kunobi-auth").unwrap();
    }
}

use super::config::ServiceConfig;
use crate::common::KunobiAuthDiscovery;
use anyhow::Context;
use std::net::IpAddr;
use std::time::Duration;

/// Fetch auth configuration from a Kunobi service, TOFU-pinned.
///
/// Calls `GET {endpoint}/.well-known/kunobi-auth` to discover the OIDC
/// provider and client configuration.
///
/// This bootstraps trust (issuer + client_id), so the transport is hardened:
/// `https` is required outside loopback, and redirects are disabled to prevent
/// a MITM from silently relocating discovery to an attacker-controlled origin.
/// The discovered issuer + audience are additionally pinned per endpoint via
/// [`TofuStore::check_and_pin`](crate::client::TofuStore::check_and_pin): the
/// first contact records them, and any later change is rejected until trust is
/// explicitly re-established with
/// [`TofuStore::trust`](crate::client::TofuStore::trust). Use
/// [`discover_with_store`] to supply a custom store, or
/// [`discover_unpinned`] to opt out (e.g. ephemeral test environments).
pub async fn discover(endpoint: &str) -> anyhow::Result<ServiceConfig> {
    discover_with_store(endpoint, &crate::client::TofuStore::new()?).await
}

/// [`discover`] with a caller-supplied TOFU store.
pub async fn discover_with_store(
    endpoint: &str,
    tofu: &crate::client::TofuStore,
) -> anyhow::Result<ServiceConfig> {
    let config = discover_unpinned(endpoint).await?;
    let result = tofu.check_and_pin(
        &config.endpoint,
        &config.issuer,
        config.audience.as_deref().unwrap_or(""),
    )?;
    if let crate::client::TofuResult::FirstConnect { .. } = result {
        tracing::info!(
            endpoint = %config.endpoint,
            issuer = %config.issuer,
            "TOFU: first contact, pinned issuer + audience for this endpoint"
        );
    }
    Ok(config)
}

/// [`discover`] without TOFU pinning. Prefer the pinned variants; this exists
/// for callers that manage endpoint trust themselves.
pub async fn discover_unpinned(endpoint: &str) -> anyhow::Result<ServiceConfig> {
    let endpoint = endpoint.trim_end_matches('/');
    let url = format!("{endpoint}/.well-known/kunobi-auth");

    enforce_secure_transport(&url, "discovery endpoint")?;

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

/// Require `https` for a trust-carrying URL (discovery endpoint, OIDC issuer,
/// token/device/revocation endpoints), allowing plaintext `http` only for
/// loopback hosts (local development / tests).
pub(crate) fn enforce_secure_transport(url: &str, what: &str) -> anyhow::Result<()> {
    let parsed =
        reqwest::Url::parse(url).with_context(|| format!("{what} URL is invalid: {url}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_url(&parsed) => Ok(()),
        "http" => anyhow::bail!("{what} must use https outside loopback hosts: {url}"),
        scheme => anyhow::bail!("{what} must use https, got {scheme}: {url}"),
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
        let err =
            enforce_secure_transport("http://service.example.com/.well-known/kunobi-auth", "test")
                .unwrap_err();
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn accepts_https_and_loopback_http() {
        enforce_secure_transport("https://service.example.com/.well-known/kunobi-auth", "t")
            .unwrap();
        enforce_secure_transport("http://127.0.0.1:8080/.well-known/kunobi-auth", "t").unwrap();
        enforce_secure_transport("http://localhost/.well-known/kunobi-auth", "t").unwrap();
        enforce_secure_transport("http://[::1]:9000/.well-known/kunobi-auth", "t").unwrap();
    }
}

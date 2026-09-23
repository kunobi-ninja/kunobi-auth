//! The authorization-code grant, end to end.
//!
//! `discover` → (`register` | pasted `client_id`) → [`authorization_url`] →
//! user consents in a browser → [`crate::oauth::callback`] receives the code →
//! [`exchange_code`] → [`crate::oauth::tokens::TokenSet`] in the keychain →
//! [`refresh_token`] thereafter.

use url::Url;

use crate::oauth::discovery::{
    AuthorizationServerMetadata, ProtectedResourceMetadata, authorization_server_metadata_urls,
    parse_www_authenticate_resource_metadata, protected_resource_metadata_urls,
};
use crate::oauth::discovery::{ClientAuthMethod, TokenEndpointAuth};
use crate::oauth::http_seam::OAuthHttp;
use crate::oauth::pkce::Pkce;
use crate::oauth::registration::ClientIdentity;
use crate::oauth::tokens::TokenSet;

/// How to find the authorization server for a connection.
///
/// All three variants produce the same [`DiscoveredAuth`]; everything
/// downstream — authorize, exchange, refresh — is identical between them.
///
/// # Why three
///
/// `ProtectedResource` is what every remote MCP server supports and what this
/// code was written for: ask the resource itself who authorizes it. Almost
/// nothing outside the MCP ecosystem publishes that document. Google is
/// reachable only from a known issuer, and GitHub publishes no discovery
/// document at all — so a crate that only knew the first would be unusable by
/// the extensions this generalisation exists to serve.
#[derive(Debug, Clone)]
pub enum ProviderResolution<'a> {
    /// RFC 9728 protected-resource metadata at the connection's own URL, then
    /// RFC 8414. The metadata hint is an out-of-band URL — a catalog entry, or
    /// one the user pasted.
    ProtectedResource {
        /// The MCP endpoint to discover the authorization server for.
        url: &'a Url,
        /// Caller-supplied resource metadata URL tried before probing.
        metadata_hint: Option<&'a Url>,
    },
    /// RFC 8414 / OIDC discovery from a known issuer.
    Issuer {
        /// The known issuer to fetch authorization-server metadata from.
        url: &'a Url,
    },
    /// Endpoints the caller states outright, for a provider that publishes no
    /// discovery document.
    ///
    /// This is NEVER reached as a fallback from a failed discovery. A discovery
    /// that fails means the server did not tell us who authorizes it; silently
    /// substituting endpoints from configuration would turn "we could not
    /// establish trust" into "we assumed some". The caller chooses this
    /// deliberately or not at all.
    Static {
        /// Used in error text, and as the identity a caller may compare
        /// against a stored one. Not verified against anything, because there
        /// is no document to verify it against.
        issuer: &'a str,
        /// The authorization endpoint stated by the caller.
        authorization_endpoint: &'a Url,
        /// The token endpoint stated by the caller.
        token_endpoint: &'a Url,
        /// Client authentication methods the token endpoint supports.
        token_endpoint_auth_methods_supported: Vec<String>,
        /// Scopes the provider supports.
        scopes_supported: Vec<String>,
    },
}

/// Everything resolution established about a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredAuth {
    /// RFC 8707 resource indicator. Sent on both the authorization and token
    /// requests so the issued token is bound to this resource and cannot be
    /// replayed against another on the same authorization server.
    ///
    /// `None` for a provider with no resource concept — an issuer or static
    /// resolution has no resource to bind to, and sending an empty or invented
    /// one risks `invalid_request` at a server that validates it.
    ///
    /// When present it is always the **requested URL**, never the value the
    /// resource-metadata document declares. A metadata resource may cover a
    /// broader URL prefix; binding to the requested URL keeps the grant narrow.
    pub resource: Option<String>,
    /// The authorization-server metadata the flow acts on.
    pub metadata: AuthorizationServerMetadata,
    /// Scopes the resource advertises, for the minimisation step.
    pub resource_scopes: Vec<String>,
}

/// Resolve the authorization server for `mcp_url`.
///
/// `caller_metadata_url` is a resource-metadata URL supplied out of band — a
/// catalog entry, or a user who pasted the one their provider documents.
///
/// Candidate order for the RFC 9728 metadata location, strongest first:
///
/// 1. the `resource_metadata` parameter of a **live** `WWW-Authenticate`
///    challenge, read here by one unauthenticated request to `mcp_url`;
/// 2. `caller_metadata_url`;
/// 3. probing `mcp_url`'s own `.well-known` paths.
///
/// The live challenge outranks the caller because it is one request old and the
/// caller's hint may be months old; a server that moves its metadata would
/// otherwise be unreconnectable until someone edited the stored hint.
///
/// All three are **candidates in a list**, not a precedence that picks one.
/// They used to be an `or_else`, which meant a challenge URL that answered 404
/// ended the search: the caller's hint, sitting right there and correct, was
/// never tried. Ordering says which is preferred; it must not say which is the
/// only one attempted.
pub async fn discover(
    http: &dyn OAuthHttp,
    mcp_url: &Url,
    caller_metadata_url: Option<&Url>,
) -> anyhow::Result<DiscoveredAuth> {
    let mut explicit: Vec<Url> = Vec::new();
    if let Some(from_challenge) = live_challenge_metadata_url(http, mcp_url).await {
        explicit.push(from_challenge);
    }
    if let Some(from_caller) = caller_metadata_url {
        explicit.push(from_caller.clone());
    }
    let prm = fetch_protected_resource_metadata(http, mcp_url, &explicit).await?;

    // RFC 9728 §3.3: the document must claim the resource we asked about. A
    // document naming someone else's resource is not a misconfiguration to
    // paper over — it is a way to point the flow at an authorization server
    // chosen by whoever wrote it.
    verify_resource_covers(&prm.resource, mcp_url)?;

    let issuer_raw = prm
        .authorization_servers
        .first()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{mcp_url} published protected-resource metadata with no authorization_servers, \
                 so there is nothing to authorize against"
            )
        })?
        .clone();
    let issuer = Url::parse(&issuer_raw)
        .map_err(|e| anyhow::anyhow!("authorization server {issuer_raw:?} is not a URL: {e}"))?;
    require_https(&issuer, "authorization server")?;

    let metadata = fetch_authorization_server_metadata(http, &issuer).await?;

    // RFC 8414 §3.3: the returned `issuer` must match the one used to build the
    // discovery URL. Skipping this check is how a compromised or misconfigured
    // resource points a client at an authorization server it does not control.
    if metadata.issuer.trim_end_matches('/') != issuer_raw.trim_end_matches('/') {
        anyhow::bail!(
            "authorization server metadata issuer {:?} does not match the advertised issuer {:?}",
            metadata.issuer,
            issuer_raw
        );
    }
    require_https(
        &Url::parse(&metadata.authorization_endpoint)?,
        "authorization endpoint",
    )?;
    require_https(&Url::parse(&metadata.token_endpoint)?, "token endpoint")?;

    Ok(DiscoveredAuth {
        resource: Some(resource_indicator(mcp_url)),
        resource_scopes: prm.scopes_supported,
        metadata,
    })
}

/// Resolve a provider by whichever strategy the caller chose.
///
/// `ProtectedResource` delegates to [`discover`] unchanged. That is deliberate
/// rather than incidental: its candidate ordering is subtle — the list is tried
/// in full, and an unparseable or 404 document at a preferred location must not
/// end the search — and the tests that hold that behaviour are written against
/// `discover`.
pub async fn resolve_provider(
    http: &dyn OAuthHttp,
    resolution: ProviderResolution<'_>,
) -> anyhow::Result<DiscoveredAuth> {
    match resolution {
        ProviderResolution::ProtectedResource { url, metadata_hint } => {
            discover(http, url, metadata_hint).await
        }
        ProviderResolution::Issuer { url } => {
            require_https(url, "authorization server")?;
            let metadata = fetch_authorization_server_metadata(http, url).await?;
            // RFC 8414 §3.3, same rule the protected-resource path applies: the
            // document must claim the issuer it was fetched for, or a
            // misconfigured host could point the flow at an authorization
            // server it does not control.
            if metadata.issuer.trim_end_matches('/') != url.as_str().trim_end_matches('/') {
                anyhow::bail!(
                    "authorization server metadata issuer {:?} does not match the issuer it was \
                     fetched from ({url})",
                    metadata.issuer
                );
            }
            require_https(
                &Url::parse(&metadata.authorization_endpoint)?,
                "authorization endpoint",
            )?;
            require_https(&Url::parse(&metadata.token_endpoint)?, "token endpoint")?;
            Ok(DiscoveredAuth {
                resource: None,
                resource_scopes: metadata.scopes_supported.clone(),
                metadata,
            })
        }
        ProviderResolution::Static {
            issuer,
            authorization_endpoint,
            token_endpoint,
            token_endpoint_auth_methods_supported,
            scopes_supported,
        } => {
            // No issuer-match check, and that is not a hole: the check defends
            // against an issuer a RESOURCE told us about. Here the endpoints came
            // from the caller's own configuration, so there is no third party's
            // claim to verify. The transport requirement still applies.
            require_https(authorization_endpoint, "authorization endpoint")?;
            require_https(token_endpoint, "token endpoint")?;
            Ok(DiscoveredAuth {
                resource: None,
                resource_scopes: scopes_supported.clone(),
                metadata: AuthorizationServerMetadata {
                    issuer: issuer.to_string(),
                    authorization_endpoint: authorization_endpoint.to_string(),
                    token_endpoint: token_endpoint.to_string(),
                    registration_endpoint: None,
                    scopes_supported,
                    // Absent means S256 is assumed supported, which is what a
                    // static provider that documents PKCE means.
                    code_challenge_methods_supported: vec![],
                    token_endpoint_auth_methods_supported: TokenEndpointAuth::Listed(
                        token_endpoint_auth_methods_supported,
                    ),
                    grant_types_supported: vec![],
                    revocation_endpoint: None,
                },
            })
        }
    }
}

/// The RFC 8707 `resource` value for `mcp_url`.
///
/// The URL that was actually requested, minus a fragment — RFC 8707 §2 requires
/// an absolute URI "without a fragment component". Not the value the
/// protected-resource document declares, and this is the whole point: the
/// resource-cover validation deliberately accepts an ancestor, so the declared
/// value may legitimately be broader than the endpoint being connected, and on
/// a multi-tenant origin "broader" means "every other tenant".
///
/// The MCP authorization spec agrees independently: a client uses the canonical
/// URI of the MCP server it is talking to.
fn resource_indicator(mcp_url: &Url) -> String {
    let mut canonical = mcp_url.clone();
    canonical.set_fragment(None);
    canonical.to_string()
}

/// One unauthenticated request to `mcp_url`, read only for its RFC 9728 §5.1
/// pointer. Every failure is swallowed: this is an optimisation over probing,
/// never a new way for a connect to fail.
///
/// A plaintext pointer is one of those failures. The challenge is unsigned data
/// from the network, so anything on the path can rewrite it — and the answer to
/// bad network data is to not follow it, not to abandon a connect the caller's
/// own https hint or the well-known probe could still complete. Refusing the
/// whole flow here would hand a passive attacker a denial of service for the
/// price of one header rewrite, while gaining nothing: the pointer is dropped
/// either way and no metadata is ever fetched over plaintext. It is logged at
/// WARN so the downgrade is visible rather than silent.
///
/// A plaintext URL from the *caller* is a different matter and is still a hard
/// error — see [`fetch_protected_resource_metadata`].
async fn live_challenge_metadata_url(http: &dyn OAuthHttp, mcp_url: &Url) -> Option<Url> {
    let resp = http.probe_challenge(mcp_url).await.ok()?;
    if resp.status != 401 {
        return None;
    }
    let url = parse_www_authenticate_resource_metadata(resp.www_authenticate.as_deref()?)?;
    if let Err(e) = require_https(&url, "resource metadata url") {
        tracing::warn!(
            %mcp_url,
            "ignoring the WWW-Authenticate resource_metadata pointer: {e}"
        );
        return None;
    }
    Some(url)
}

/// RFC 9728 §3.3, with the comparison rule written out.
///
/// The declared `resource` must **cover** `mcp_url`: same origin (scheme, host
/// and port), and the declared path must be `mcp_url`'s path or an ancestor of
/// it. Not string equality — `mcp.adplane.ai` serves
/// `{"resource": "https://mcp.adplane.ai"}` for an MCP endpoint at
/// `https://mcp.adplane.ai/mcp`, which is legal, and equality would reject a
/// working server. Trailing slashes and empty segments are normalised away on
/// both sides, so `https://h/mcp/` and `https://h/mcp` are the same resource.
///
/// # Why "covers" is safe here but would not be as a token audience
///
/// Accepting an ancestor is a rule about *whose document this is*: it decides
/// whether to trust the `authorization_servers` it names. It is deliberately
/// NOT the value sent as the RFC 8707 `resource` — see [`resource_indicator`].
/// The two used to be the same string, and that made the leniency dangerous on
/// a shared origin: a hostile MCP server at `https://api.example/attacker/mcp`
/// can declare `resource: "https://api.example/"`, which covers its own path
/// perfectly well, and the user would then have consented to a token whose
/// audience is every tenant on that host — replayable against
/// `https://api.example/victim/...`. Tightening the rule to equality is not the
/// answer (it rejects adplane and every server shaped like it); sending the
/// requested URL is.
///
/// The origin is the load-bearing half of what remains: it is what decides
/// whether the document may speak for this server at all.
///
/// Query, fragment and userinfo are refused outright rather than compared: RFC
/// 8707 §2 has no place for them in a resource identifier, the cover comparison
/// below looks only at origin and path, and a `?tenant=victim` that nothing
/// examines is precisely the shape of the leniency this function exists to
/// bound.
fn verify_resource_covers(declared: &str, mcp_url: &Url) -> anyhow::Result<()> {
    // An empty `resource` means the field was absent or blank; `discover` then
    // falls back to `mcp_url` itself, so there is nothing to be retargeted.
    if declared.is_empty() {
        return Ok(());
    }
    let declared_url = Url::parse(declared).map_err(|e| {
        anyhow::anyhow!(
            "protected-resource metadata declared resource {declared:?}, not a URL: {e}"
        )
    })?;
    if declared_url.query().is_some()
        || declared_url.fragment().is_some()
        || !declared_url.username().is_empty()
        || declared_url.password().is_some()
    {
        anyhow::bail!(
            "protected-resource metadata declared resource {declared:?}, which is not a resource \
             identifier: RFC 8707 §2 allows no query, fragment or userinfo component."
        )
    }
    let same_origin = declared_url.scheme() == mcp_url.scheme()
        && declared_url.host_str() == mcp_url.host_str()
        && declared_url.port_or_known_default() == mcp_url.port_or_known_default();
    let segments = |u: &Url| -> Vec<String> {
        u.path()
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    };
    let declared_path = segments(&declared_url);
    let target_path = segments(mcp_url);
    let is_ancestor = declared_path.len() <= target_path.len()
        && declared_path
            .iter()
            .zip(target_path.iter())
            .all(|(a, b)| a == b);
    if same_origin && is_ancestor {
        return Ok(());
    }
    anyhow::bail!(
        "protected-resource metadata declares resource {declared:?}, which does not cover \
         {mcp_url}. RFC 9728 §3.3 requires the document to identify the resource it was \
         fetched for; adopting a foreign identifier would audience-bind the token to it."
    )
}

async fn fetch_protected_resource_metadata(
    http: &dyn OAuthHttp,
    mcp_url: &Url,
    explicit_metadata_urls: &[Url],
) -> anyhow::Result<ProtectedResourceMetadata> {
    let mut candidates: Vec<Url> = Vec::new();
    for c in explicit_metadata_urls {
        // The well-known candidates are derived from an already-validated https
        // `mcp_url`; these are not, so they are the only metadata URLs that can
        // be plaintext. A plaintext one from the challenge was already dropped
        // upstream; one that reaches here came from a tool argument, i.e. a
        // catalog entry or something the user pasted. That is a configuration
        // error with no attacker in the loop, and failing loudly is the useful
        // answer — quietly falling back would leave the wrong URL in place,
        // still wrong, on every future connect.
        require_https(c, "resource metadata url")?;
        candidates.push(c.clone());
    }
    candidates.extend(protected_resource_metadata_urls(mcp_url));

    for url in &candidates {
        let resp = http.get_json(url).await?;
        if !resp.is_success() {
            continue;
        }
        // A candidate that answers but does not parse is skipped, not fatal: the
        // list is tried in full, and an unparseable document at a preferred
        // location must not shadow a correct one further down.
        if let Some(body) = resp.body.clone()
            && let Ok(prm) = serde_json::from_value::<ProtectedResourceMetadata>(body)
        {
            return Ok(prm);
        }
    }
    anyhow::bail!(
        "no RFC 9728 protected-resource metadata found for {mcp_url} (tried {})",
        candidates
            .iter()
            .map(Url::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

async fn fetch_authorization_server_metadata(
    http: &dyn OAuthHttp,
    issuer: &Url,
) -> anyhow::Result<AuthorizationServerMetadata> {
    let candidates = authorization_server_metadata_urls(issuer);
    for url in &candidates {
        let resp = http.get_json(url).await?;
        if !resp.is_success() {
            continue;
        }
        if let Some(body) = resp.body.clone()
            && let Ok(md) = serde_json::from_value::<AuthorizationServerMetadata>(body)
        {
            return Ok(md);
        }
    }
    anyhow::bail!(
        "no RFC 8414 authorization-server metadata found for {issuer} (tried {})",
        candidates
            .iter()
            .map(Url::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn require_https(url: &Url, what: &str) -> anyhow::Result<()> {
    let is_loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if url.scheme() == "https" || (url.scheme() == "http" && is_loopback) {
        return Ok(());
    }
    anyhow::bail!("{what} {url} must use https (loopback http is allowed for local testing only)")
}

/// Everything needed to build the authorization request.
pub struct AuthorizeParams<'a> {
    /// The client identifier sent on the authorization request.
    pub client_id: &'a str,
    /// The redirect URI sent on the authorization request.
    pub redirect_uri: &'a str,
    /// The scopes requested on the authorization request.
    pub scopes: &'a [String],
    /// RFC 8707 audience. `None` for a provider with no resource concept —
    /// discovery from an issuer or from statically declared endpoints yields no
    /// resource, and sending an empty or invented one risks `invalid_request`.
    pub resource: Option<&'a str>,
    /// The state nonce sent on the authorization request.
    pub state: &'a str,
    /// The PKCE pair proving the exchange belongs to this flow.
    pub pkce: &'a Pkce,
}

/// Parameters the flow owns. A caller-supplied extra that collided with one of
/// these could redirect the grant elsewhere, downgrade PKCE, or replace the
/// state nonce, so they are refused by name rather than silently overwritten.
pub const RESERVED_AUTHORIZE_PARAMS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "state",
    "code_challenge",
    "code_challenge_method",
    "resource",
    "scope",
];

/// Build the browser URL the user is sent to.
pub fn authorization_url(
    metadata: &AuthorizationServerMetadata,
    params: &AuthorizeParams<'_>,
) -> anyhow::Result<Url> {
    authorization_url_with(metadata, params, &[])
}

/// [`authorization_url`], plus provider-specific parameters.
///
/// Google needs `access_type=offline` to issue a refresh token at all, and
/// `prompt=consent` to re-issue one on a repeat authorization. Neither is in
/// any RFC, and a flow that could not express them would produce a connection
/// that silently needs re-consent every hour.
pub fn authorization_url_with(
    metadata: &AuthorizationServerMetadata,
    params: &AuthorizeParams<'_>,
    extra: &[(String, String)],
) -> anyhow::Result<Url> {
    for (key, _) in extra {
        if RESERVED_AUTHORIZE_PARAMS
            .iter()
            .any(|r| r.eq_ignore_ascii_case(key))
        {
            anyhow::bail!(
                "{key:?} is set by the flow and may not be overridden by a provider parameter"
            );
        }
    }
    let mut url = authorization_url_inner(metadata, params)?;
    {
        let mut q = url.query_pairs_mut();
        for (key, value) in extra {
            q.append_pair(key, value);
        }
    }
    Ok(url)
}

fn authorization_url_inner(
    metadata: &AuthorizationServerMetadata,
    params: &AuthorizeParams<'_>,
) -> anyhow::Result<Url> {
    if !metadata.supports_s256() {
        anyhow::bail!(
            "{} advertises PKCE methods {:?} and not S256; Kunobi will not downgrade to plain",
            metadata.issuer,
            metadata.code_challenge_methods_supported
        );
    }
    let mut url = Url::parse(&metadata.authorization_endpoint)?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", params.client_id);
        q.append_pair("redirect_uri", params.redirect_uri);
        q.append_pair("state", params.state);
        q.append_pair("code_challenge", params.pkce.challenge());
        q.append_pair("code_challenge_method", Pkce::METHOD);
        // RFC 8707, when there is a resource to bind to. An authorization server
        // that does not understand the parameter must ignore it, so sending it
        // to one that does not is harmless — but sending an EMPTY or invented
        // one to a server that DOES validate it is not, which is why this is
        // conditional rather than always-on.
        if let Some(resource) = params.resource {
            q.append_pair("resource", resource);
        }
        if !params.scopes.is_empty() {
            q.append_pair("scope", &params.scopes.join(" "));
        }
    }
    Ok(url)
}

/// Apply the selected client authentication to a token request.
///
/// Returns the HTTP Basic pair, if any, after adjusting `form` in place.
///
/// # Why `client_id` leaves the body for Basic
///
/// RFC 6749 §2.3.1: a client MUST NOT use more than one authentication method
/// in a single request. Sending `client_id` in the form while also sending
/// Basic credentials is exactly that, and strict servers reject it — with an
/// error that names neither cause.
///
/// # Why the Basic halves are form-encoded first
///
/// The same section requires the client id and secret to be encoded with
/// `application/x-www-form-urlencoded` BEFORE they are joined by a colon and
/// base64ed. Handing the raw values to an HTTP client's `basic_auth` skips
/// that step, and it is not cosmetic: a secret containing `:` splits the
/// credential in the wrong place, and one containing `+` or `/` decodes to
/// different bytes at the server. Both produce `invalid_client` against a
/// correct provider, with nothing in the error naming the cause.
///
/// Encoded here rather than in the HTTP implementation so the fake and the real
/// client carry identical bytes — otherwise a test asserting the pair proves
/// nothing about the wire.
/// `application/x-www-form-urlencoded` encoding of one Basic credential half.
fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn apply_client_auth(
    form: &mut Vec<(String, String)>,
    client_id: &str,
    client_secret: Option<&str>,
    method: ClientAuthMethod,
) -> Option<(String, String)> {
    match (method, client_secret) {
        (ClientAuthMethod::Basic, Some(secret)) => {
            form.retain(|(k, _)| k != "client_id");
            Some((form_encode(client_id), form_encode(secret)))
        }
        (ClientAuthMethod::Post, Some(secret)) => {
            form.push(("client_secret".to_string(), secret.to_string()));
            None
        }
        // A public client, or a confidential method with no secret to send: the
        // request stays as it is and PKCE carries the proof.
        _ => None,
    }
}

/// Redeem an authorization code for a token set.
pub async fn exchange_code(
    http: &dyn OAuthHttp,
    metadata: &AuthorizationServerMetadata,
    identity: &ClientIdentity,
    redirect_uri: &str,
    resource: Option<&str>,
    code: &str,
    pkce: &Pkce,
) -> anyhow::Result<TokenSet> {
    let client_id = identity.client_id();
    let secret = identity.client_secret();
    // Refuse BEFORE the browser opens, not after the user has consented: a
    // consent that cannot be redeemed wastes the only step that needs a human.
    if secret.is_none() && !metadata.allows_public_client() {
        anyhow::bail!(
            "{} requires token-endpoint client authentication ({:?}), and this connection has no \
             client secret. Register an app with the provider and supply its client id and \
             secret, or use a provider that supports dynamic registration.",
            metadata.issuer,
            metadata.token_endpoint_auth_methods_supported.listed()
        );
    }
    let method = if secret.is_some() {
        metadata.select_client_auth()?
    } else {
        ClientAuthMethod::None
    };
    let mut form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), code.to_string()),
        ("redirect_uri".to_string(), redirect_uri.to_string()),
        ("client_id".to_string(), client_id.to_string()),
        ("code_verifier".to_string(), pkce.verifier().to_string()),
    ];
    // Must match what the authorization request sent, or a server that
    // audience-binds rejects the exchange.
    if let Some(resource) = resource {
        form.push(("resource".to_string(), resource.to_string()));
    }
    let basic = apply_client_auth(&mut form, client_id, secret, method);
    let token_endpoint = Url::parse(&metadata.token_endpoint)?;
    let resp = http.post_form(&token_endpoint, &form, basic).await?;
    if !resp.is_success() {
        anyhow::bail!("token exchange failed — {}", resp.error_summary());
    }
    TokenSet::from_token_response(
        resp.body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("token endpoint returned a non-JSON body"))?,
    )
}

/// Exchange a refresh token for a fresh access token.
///
/// A server that omits `refresh_token` in the response is rotating nothing, so
/// the previous refresh token is carried forward; a server that returns a new
/// one has rotated and the old one is now dead. Getting this backwards produces
/// a connection that works once and then cannot refresh again.
pub async fn refresh_token(
    http: &dyn OAuthHttp,
    metadata: &AuthorizationServerMetadata,
    client_id: &str,
    client_secret: Option<&str>,
    resource: Option<&str>,
    refresh: &str,
    scopes: &[String],
) -> anyhow::Result<TokenSet> {
    let mut form = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("refresh_token".to_string(), refresh.to_string()),
        ("client_id".to_string(), client_id.to_string()),
    ];
    if let Some(resource) = resource {
        form.push(("resource".to_string(), resource.to_string()));
    }
    if !scopes.is_empty() {
        form.push(("scope".to_string(), scopes.join(" ")));
    }
    let method = if client_secret.is_some() {
        metadata.select_client_auth()?
    } else {
        ClientAuthMethod::None
    };
    let basic = apply_client_auth(&mut form, client_id, client_secret, method);
    let token_endpoint = Url::parse(&metadata.token_endpoint)?;
    let resp = http.post_form(&token_endpoint, &form, basic).await?;
    if !resp.is_success() {
        anyhow::bail!("token refresh failed — {}", resp.error_summary());
    }
    let mut set = TokenSet::from_token_response(
        resp.body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("token endpoint returned a non-JSON body"))?,
    )?;
    if set.refresh_token.is_none() {
        set.refresh_token = Some(refresh.to_string());
    }
    Ok(set)
}

/// Choose the scopes to request.
///
/// The safety rule from the design review: request the smallest set that could
/// work and step up later, never the server's whole `scopes_supported` list. A
/// connected X grants `developer.billing.write` — the ability to spend money —
/// and a connected Slack grants `chat:write` and `search:read.private`, to a
/// credential every agent behind the gateway shares.
///
/// So: an explicit user/catalog request wins; otherwise send nothing and let the
/// authorization server apply its own default, which is invariably narrower
/// than the union of everything it supports.
pub fn minimal_scopes(requested: &[String], _supported: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in requested {
        let s = s.trim();
        if !s.is_empty() && !out.iter().any(|e| e == s) {
            out.push(s.to_string());
        }
    }
    out
}

/// Best-effort RFC 7009 revocation of a token at the provider.
///
/// # Why best-effort, and why it still matters
///
/// A user who disconnects expects the grant to be gone — including from the
/// provider's authorized-apps list. Removing only the local copy leaves it live,
/// which is a security expectation gap rather than a cosmetic one.
///
/// But a revocation that fails must never block the local removal: the network
/// may be down, the provider may not implement RFC 7009, and refusing to
/// disconnect because of either would leave the user unable to remove a
/// credential they no longer want. So this reports what happened and the caller
/// removes locally regardless.
///
/// `Ok(false)` means the server published no revocation endpoint — nothing was
/// attempted, and nothing was wrong.
pub async fn revoke_token(
    http: &dyn OAuthHttp,
    metadata: &AuthorizationServerMetadata,
    client_id: &str,
    client_secret: Option<&str>,
    token: &str,
    token_type_hint: &str,
) -> anyhow::Result<bool> {
    let Some(endpoint) = metadata.revocation_endpoint.as_deref() else {
        return Ok(false);
    };
    let endpoint = Url::parse(endpoint)?;
    require_https(&endpoint, "revocation endpoint")?;

    let mut form = vec![
        ("token".to_string(), token.to_string()),
        ("token_type_hint".to_string(), token_type_hint.to_string()),
        ("client_id".to_string(), client_id.to_string()),
    ];
    let method = if client_secret.is_some() {
        metadata.select_client_auth()?
    } else {
        ClientAuthMethod::None
    };
    let basic = apply_client_auth(&mut form, client_id, client_secret, method);

    let resp = http.post_form(&endpoint, &form, basic).await?;
    if !resp.is_success() {
        anyhow::bail!("revocation was refused — {}", resp.error_summary());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::discovery::TokenEndpointAuth;
    use crate::oauth::http_seam::FakeHttp;

    /// The public-client identity most of these tests use.
    fn public(client_id: &str) -> ClientIdentity {
        ClientIdentity::Registered {
            client_id: client_id.to_string(),
        }
    }
    use crate::oauth::pkce::Pkce;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn md() -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: "https://auth.example.com".into(),
            authorization_endpoint: "https://auth.example.com/authorize".into(),
            token_endpoint: "https://auth.example.com/token".into(),
            registration_endpoint: Some("https://auth.example.com/register".into()),
            scopes_supported: vec!["read".into(), "write".into(), "billing.write".into()],
            code_challenge_methods_supported: vec!["S256".into()],
            token_endpoint_auth_methods_supported: TokenEndpointAuth::Listed(vec!["none".into()]),
            grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
            revocation_endpoint: None,
        }
    }

    /// The "standard" category end to end: protected-resource metadata at the
    /// path-insertion URL, authorization-server metadata at the RFC 8414
    /// path-insertion URL. This is the shape a naive appending-first client
    /// misses.
    #[tokio::test]
    async fn discovers_through_path_insertion_metadata() {
        let http = FakeHttp::default()
            .with_get(
                "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                FakeHttp::json(
                    200,
                    serde_json::json!({
                        "resource": "https://mcp.example.com/mcp",
                        "authorization_servers": ["https://auth.example.com/v1"],
                        "scopes_supported": ["read", "write"]
                    }),
                ),
            )
            .with_get(
                "https://auth.example.com/.well-known/oauth-authorization-server/v1",
                FakeHttp::json(
                    200,
                    serde_json::json!({
                        "issuer": "https://auth.example.com/v1",
                        "authorization_endpoint": "https://auth.example.com/v1/authorize",
                        "token_endpoint": "https://auth.example.com/v1/token",
                        "registration_endpoint": "https://auth.example.com/v1/register",
                        "token_endpoint_auth_methods_supported": ["none"],
                        "code_challenge_methods_supported": ["S256"]
                    }),
                ),
            );
        let d = discover(&http, &u("https://mcp.example.com/mcp"), None)
            .await
            .unwrap();
        assert_eq!(d.resource.as_deref(), Some("https://mcp.example.com/mcp"));
        assert_eq!(d.metadata.issuer, "https://auth.example.com/v1");
        assert_eq!(d.resource_scopes, vec!["read", "write"]);
    }

    /// The authorization-server document, scripted at its root well-known URL.
    fn as_metadata(http: FakeHttp) -> FakeHttp {
        http.with_get(
            "https://auth.example.com/.well-known/oauth-authorization-server",
            FakeHttp::json(200, serde_json::to_value(md()).unwrap()),
        )
    }

    fn prm_json(resource: &str) -> serde_json::Value {
        serde_json::json!({
            "resource": resource,
            "authorization_servers": ["https://auth.example.com"]
        })
    }

    fn bearer(metadata_url: &str) -> String {
        format!(r#"Bearer error="invalid_token", resource_metadata="{metadata_url}""#)
    }

    /// The shape this whole path exists for: the MCP server publishes nothing
    /// under its own `.well-known` (both probes 404) and names its metadata on
    /// a different host in the `WWW-Authenticate` challenge. Before the live
    /// probe existed, `discover` never saw that header and failed with "no RFC
    /// 9728 protected-resource metadata found" before a browser could open.
    #[tokio::test]
    async fn a_live_challenge_naming_another_host_is_followed() {
        let http = as_metadata(
            FakeHttp::default()
                .with_challenge(
                    "https://mcp.example.com/mcp",
                    &bearer(
                        "https://metadata.elsewhere.example/.well-known/oauth-protected-resource",
                    ),
                )
                .with_get(
                    "https://metadata.elsewhere.example/.well-known/oauth-protected-resource",
                    FakeHttp::json(200, prm_json("https://mcp.example.com/mcp")),
                ),
        );
        let d = discover(&http, &u("https://mcp.example.com/mcp"), None)
            .await
            .unwrap();
        assert_eq!(d.metadata.token_endpoint, "https://auth.example.com/token");
        assert_eq!(d.resource.as_deref(), Some("https://mcp.example.com/mcp"));
    }

    #[tokio::test]
    async fn a_caller_supplied_metadata_url_is_used_when_there_is_no_live_challenge() {
        let http = as_metadata(FakeHttp::default().with_get(
            "https://elsewhere.example/prm",
            FakeHttp::json(200, prm_json("https://mcp.example.com/mcp")),
        ));
        let d = discover(
            &http,
            &u("https://mcp.example.com/mcp"),
            Some(&u("https://elsewhere.example/prm")),
        )
        .await
        .unwrap();
        assert_eq!(d.metadata.token_endpoint, "https://auth.example.com/token");
    }

    /// Precedence. A caller-supplied URL is a hint recorded at some earlier
    /// time — from a catalog entry, or a user who pasted it. The challenge came
    /// from the server one request ago, so it is the fresher of the two and
    /// wins; otherwise a server that moved its metadata could never be
    /// reconnected without editing the stored hint first.
    #[tokio::test]
    async fn a_live_challenge_wins_over_a_caller_supplied_url() {
        let http = as_metadata(
            FakeHttp::default()
                .with_challenge(
                    "https://mcp.example.com/mcp",
                    &bearer("https://fresh.example/prm"),
                )
                .with_get(
                    "https://fresh.example/prm",
                    FakeHttp::json(200, prm_json("https://mcp.example.com/mcp")),
                )
                .with_get(
                    "https://stale.example/prm",
                    FakeHttp::json(
                        200,
                        serde_json::json!({
                            "resource": "https://mcp.example.com/mcp",
                            "authorization_servers": ["https://stale-auth.example.com"]
                        }),
                    ),
                ),
        );
        let d = discover(
            &http,
            &u("https://mcp.example.com/mcp"),
            Some(&u("https://stale.example/prm")),
        )
        .await
        .unwrap();
        assert_eq!(
            d.metadata.issuer, "https://auth.example.com",
            "the live challenge must win over the caller's stale hint"
        );
    }

    /// Regression guard for the servers that work today: no challenge, no
    /// caller URL, so the well-known probing must behave exactly as before.
    /// The probe is best-effort and a server that answers it with anything but
    /// a 401-plus-challenge must cost nothing.
    #[tokio::test]
    async fn without_a_challenge_or_a_caller_url_the_well_known_probe_is_unchanged() {
        let http = as_metadata(FakeHttp::default().with_get(
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            FakeHttp::json(200, prm_json("https://mcp.example.com/mcp")),
        ));
        let d = discover(&http, &u("https://mcp.example.com/mcp"), None)
            .await
            .unwrap();
        assert_eq!(d.metadata.token_endpoint, "https://auth.example.com/token");
    }

    /// RFC 9728 §3.3. The `resource` we adopt here becomes the RFC 8707
    /// `resource` on both the authorization and the token request, i.e. the
    /// audience of the token that ends up in the keychain. A metadata document
    /// that names someone else's resource therefore retargets that audience;
    /// combined with a challenge we now follow to an arbitrary host, that is a
    /// token-theft primitive rather than a misconfiguration.
    #[tokio::test]
    async fn refuses_metadata_whose_resource_names_a_different_server() {
        let http = as_metadata(FakeHttp::default().with_get(
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            FakeHttp::json(200, prm_json("https://victim.example.com/mcp")),
        ));
        let err = discover(&http, &u("https://mcp.example.com/mcp"), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not cover"), "{err}");
    }

    /// The comparison rule, pinned against a live server. `mcp.adplane.ai`
    /// serves `{"resource": "https://mcp.adplane.ai"}` for an MCP endpoint at
    /// `https://mcp.adplane.ai/mcp` — legal, because a resource identifier may
    /// cover a whole origin. String equality would reject a working server, so
    /// the rule is "same origin, and the declared path is an ancestor".
    ///
    /// Accepting it for discovery is not the same as adopting it as the token
    /// audience: see `sends_the_requested_mcp_url_as_the_resource_indicator`.
    #[tokio::test]
    async fn accepts_an_origin_level_resource_identifier() {
        let http = as_metadata(FakeHttp::default().with_get(
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            FakeHttp::json(200, prm_json("https://mcp.example.com")),
        ));
        let d = discover(&http, &u("https://mcp.example.com/mcp"), None)
            .await
            .unwrap();
        assert_eq!(d.resource.as_deref(), Some("https://mcp.example.com/mcp"));
    }

    /// The multi-tenant origin. `https://api.example/attacker/mcp` publishes a
    /// document declaring the whole origin as its resource, which the cover
    /// rule accepts (it has to — see the adplane test above). Adopting that
    /// declared value as the RFC 8707 `resource` would mint a token whose
    /// audience is every tenant on `api.example`, and hand it to the tenant
    /// who asked. The audience must never be wider than the server actually
    /// being connected.
    #[tokio::test]
    async fn a_broad_declared_resource_does_not_widen_the_token_audience() {
        let http = as_metadata(FakeHttp::default().with_get(
            "https://api.example/.well-known/oauth-protected-resource/attacker/mcp",
            FakeHttp::json(200, prm_json("https://api.example/")),
        ));
        let d = discover(&http, &u("https://api.example/attacker/mcp"), None)
            .await
            .unwrap();
        assert_eq!(
            d.resource.as_deref(),
            Some("https://api.example/attacker/mcp"),
            "the indicator must name the requested MCP server, not the origin \
             it happens to share with every other tenant"
        );
    }

    /// RFC 8707 §2: the resource indicator is the MCP server's own URI, and the
    /// MCP authorization spec says the same. So it is derived from what was
    /// asked for, never from what the document claims — even when the claim is
    /// exactly right.
    #[tokio::test]
    async fn sends_the_requested_mcp_url_as_the_resource_indicator() {
        let http = as_metadata(FakeHttp::default().with_get(
            "https://mcp.example.com/.well-known/oauth-protected-resource/a/b",
            FakeHttp::json(200, prm_json("https://mcp.example.com/a")),
        ));
        let d = discover(&http, &u("https://mcp.example.com/a/b#frag"), None)
            .await
            .unwrap();
        assert_eq!(
            d.resource.as_deref(),
            Some("https://mcp.example.com/a/b"),
            "RFC 8707 §2 forbids a fragment on a resource indicator"
        );
    }

    /// A declared `resource` carrying a query, a fragment or userinfo is not a
    /// resource identifier (RFC 8707 §2), and the cover rule compares only
    /// scheme, host, port and path — so those components would pass unexamined.
    #[tokio::test]
    async fn refuses_a_declared_resource_with_query_fragment_or_userinfo() {
        for declared in [
            "https://mcp.example.com/mcp?tenant=victim",
            "https://mcp.example.com/mcp#frag",
            "https://user:pw@mcp.example.com/mcp",
        ] {
            let http = as_metadata(FakeHttp::default().with_get(
                "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                FakeHttp::json(200, prm_json(declared)),
            ));
            let err = discover(&http, &u("https://mcp.example.com/mcp"), None)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("resource identifier"), "{declared}: {err}");
        }
    }

    /// A sibling path is not an ancestor: `/other` must not authorize `/mcp`.
    #[tokio::test]
    async fn refuses_a_sibling_path_resource_identifier() {
        let http = as_metadata(FakeHttp::default().with_get(
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            FakeHttp::json(200, prm_json("https://mcp.example.com/other")),
        ));
        let err = discover(&http, &u("https://mcp.example.com/mcp"), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not cover"), "{err}");
    }

    /// A plaintext pointer in the challenge is dropped, never fetched. With
    /// nothing else to try, the connect fails at the well-known probe — the
    /// same shape as a server that publishes no metadata at all.
    #[tokio::test]
    async fn never_fetches_a_plaintext_metadata_url_from_a_challenge() {
        let http = as_metadata(FakeHttp::default().with_challenge(
            "https://mcp.example.com/mcp",
            &bearer("http://attacker.example/prm"),
        ));
        let err = discover(&http, &u("https://mcp.example.com/mcp"), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("attacker.example"),
            "the plaintext pointer must not even become a candidate: {err}"
        );
        assert!(err.contains("no RFC 9728"), "{err}");
    }

    /// The denial of service the old hard refusal handed to anyone who could
    /// rewrite one header: a rewritten challenge must not take out a connect
    /// the caller's own https hint completes perfectly well.
    #[tokio::test]
    async fn a_plaintext_challenge_pointer_does_not_block_a_valid_caller_url() {
        let http = as_metadata(
            FakeHttp::default()
                .with_challenge(
                    "https://mcp.example.com/mcp",
                    &bearer("http://attacker.example/prm"),
                )
                .with_get(
                    "https://caller.example/prm",
                    FakeHttp::json(200, prm_json("https://mcp.example.com/mcp")),
                ),
        );
        let d = discover(
            &http,
            &u("https://mcp.example.com/mcp"),
            Some(&u("https://caller.example/prm")),
        )
        .await
        .unwrap();
        assert_eq!(d.metadata.token_endpoint, "https://auth.example.com/token");
    }

    /// Ordering is a preference, not an exclusive choice. The challenge URL is
    /// tried first and 404s; the caller's hint must then be tried, rather than
    /// the search ending because one explicit URL had already been picked.
    #[tokio::test]
    async fn a_challenge_url_that_404s_falls_through_to_the_caller_url() {
        let http = as_metadata(
            FakeHttp::default()
                .with_challenge(
                    "https://mcp.example.com/mcp",
                    &bearer("https://moved.example/prm"),
                )
                .with_get(
                    "https://caller.example/prm",
                    FakeHttp::json(200, prm_json("https://mcp.example.com/mcp")),
                ),
        );
        let d = discover(
            &http,
            &u("https://mcp.example.com/mcp"),
            Some(&u("https://caller.example/prm")),
        )
        .await
        .unwrap();
        assert_eq!(d.metadata.token_endpoint, "https://auth.example.com/token");
    }

    #[tokio::test]
    async fn refuses_a_plaintext_metadata_url_from_the_caller() {
        let http = as_metadata(FakeHttp::default());
        let err = discover(
            &http,
            &u("https://mcp.example.com/mcp"),
            Some(&u("http://attacker.example/prm")),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("must use https"), "{err}");
    }

    /// RFC 8414 §3.3. Without it, a resource can name any authorization server
    /// and the client will happily send the user there and accept its tokens.
    #[tokio::test]
    async fn refuses_metadata_whose_issuer_does_not_match() {
        let http = FakeHttp::default()
            .with_get(
                "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                FakeHttp::json(
                    200,
                    serde_json::json!({
                        "resource": "https://mcp.example.com/mcp",
                        "authorization_servers": ["https://auth.example.com"]
                    }),
                ),
            )
            .with_get(
                "https://auth.example.com/.well-known/oauth-authorization-server",
                FakeHttp::json(
                    200,
                    serde_json::json!({
                        "issuer": "https://evil.example.com",
                        "authorization_endpoint": "https://evil.example.com/a",
                        "token_endpoint": "https://evil.example.com/t"
                    }),
                ),
            );
        let err = discover(&http, &u("https://mcp.example.com/mcp"), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[tokio::test]
    async fn refuses_a_plaintext_authorization_endpoint() {
        let http = FakeHttp::default()
            .with_get(
                "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                FakeHttp::json(
                    200,
                    serde_json::json!({
                        "resource": "https://mcp.example.com/mcp",
                        "authorization_servers": ["https://auth.example.com"]
                    }),
                ),
            )
            .with_get(
                "https://auth.example.com/.well-known/oauth-authorization-server",
                FakeHttp::json(
                    200,
                    serde_json::json!({
                        "issuer": "https://auth.example.com",
                        "authorization_endpoint": "http://auth.example.com/a",
                        "token_endpoint": "https://auth.example.com/t"
                    }),
                ),
            );
        let err = discover(&http, &u("https://mcp.example.com/mcp"), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("must use https"), "{err}");
    }

    #[tokio::test]
    async fn missing_protected_resource_metadata_names_what_was_tried() {
        let http = FakeHttp::default();
        let err = discover(&http, &u("https://mcp.example.com/mcp"), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("/.well-known/oauth-protected-resource/mcp"),
            "{err}"
        );
    }

    /// RFC 8707 is only meaningful when there IS a resource. Discovery from a
    /// bare issuer (Google) or from statically declared endpoints (GitHub)
    /// produces none, and sending `resource=` empty — or inventing one — is
    /// rejected outright by servers that validate the parameter.
    #[test]
    fn no_resource_means_no_resource_parameter() {
        let pkce = Pkce::from_verifier("v".repeat(43));
        let url = authorization_url(
            &md(),
            &AuthorizeParams {
                client_id: "cid",
                redirect_uri: "http://127.0.0.1:41234/callback",
                scopes: &["read".to_string()],
                resource: None,
                state: "st",
                pkce: &pkce,
            },
        )
        .unwrap();
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert!(
            !q.contains_key("resource"),
            "an absent audience must be absent from the request, not empty: {q:?}"
        );
        // Everything else still travels.
        assert_eq!(q["client_id"], "cid");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["state"], "st");
    }

    #[tokio::test]
    async fn a_resourceless_exchange_sends_no_resource_field() {
        let http = FakeHttp::default().with_post(
            "https://auth.example.com/token",
            FakeHttp::json(
                200,
                serde_json::json!({"access_token": "at", "token_type": "Bearer"}),
            ),
        );
        let pkce = Pkce::from_verifier("v".repeat(43));
        exchange_code(
            &http,
            &md(),
            &public("cid"),
            "http://127.0.0.1:1/callback",
            None,
            "the-code",
            &pkce,
        )
        .await
        .unwrap();

        let form = http.last_form().expect("a token request was made");
        assert!(
            !form.iter().any(|(k, _)| k == "resource"),
            "the token exchange must match the authorization request, which sent \
             no resource: {form:?}"
        );
        assert!(
            form.iter()
                .any(|(k, v)| k == "code_verifier" && !v.is_empty())
        );
    }

    #[tokio::test]
    async fn a_resourceless_refresh_sends_no_resource_field() {
        let http = FakeHttp::default().with_post(
            "https://auth.example.com/token",
            FakeHttp::json(
                200,
                serde_json::json!({"access_token": "at2", "token_type": "Bearer"}),
            ),
        );
        refresh_token(&http, &md(), "cid", None, None, "old-rt", &[])
            .await
            .unwrap();

        let form = http.last_form().expect("a refresh request was made");
        assert!(!form.iter().any(|(k, _)| k == "resource"), "{form:?}");
    }

    #[test]
    fn authorization_url_carries_pkce_state_and_resource() {
        let pkce = Pkce::from_verifier("v".repeat(43));
        let url = authorization_url(
            &md(),
            &AuthorizeParams {
                client_id: "cid",
                redirect_uri: "http://127.0.0.1:41234/callback",
                scopes: &["read".to_string()],
                resource: Some("https://mcp.example.com/mcp"),
                state: "st",
                pkce: &pkce,
            },
        )
        .unwrap();
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], "cid");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["code_challenge"], pkce.challenge());
        assert_eq!(q["state"], "st");
        assert_eq!(q["resource"], "https://mcp.example.com/mcp");
        assert_eq!(q["scope"], "read");
        assert_eq!(q["redirect_uri"], "http://127.0.0.1:41234/callback");
        // The verifier must never appear in the browser URL.
        assert!(!url.as_str().contains(pkce.verifier()));
    }

    #[test]
    fn authorization_url_omits_scope_when_minimised_to_nothing() {
        let pkce = Pkce::from_verifier("v".repeat(43));
        let url = authorization_url(
            &md(),
            &AuthorizeParams {
                client_id: "cid",
                redirect_uri: "http://127.0.0.1:1/callback",
                scopes: &[],
                resource: Some("r"),
                state: "st",
                pkce: &pkce,
            },
        )
        .unwrap();
        assert!(url.query_pairs().all(|(k, _)| k != "scope"));
    }

    #[test]
    fn authorization_url_refuses_a_server_that_only_offers_plain() {
        let mut m = md();
        m.code_challenge_methods_supported = vec!["plain".into()];
        let pkce = Pkce::from_verifier("v".repeat(43));
        let err = authorization_url(
            &m,
            &AuthorizeParams {
                client_id: "c",
                redirect_uri: "http://127.0.0.1:1/callback",
                scopes: &[],
                resource: Some("r"),
                state: "s",
                pkce: &pkce,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("S256"), "{err}");
    }

    #[tokio::test]
    async fn exchange_sends_the_verifier_and_the_resource() {
        let http = FakeHttp::default().with_post(
            "https://auth.example.com/token",
            FakeHttp::json(
                200,
                serde_json::json!({
                    "access_token": "at", "token_type": "Bearer",
                    "expires_in": 3600, "refresh_token": "rt", "scope": "read"
                }),
            ),
        );
        let pkce = Pkce::from_verifier("v".repeat(43));
        let set = exchange_code(
            &http,
            &md(),
            &public("cid"),
            "http://127.0.0.1:1/callback",
            Some("https://mcp.example.com/mcp"),
            "the-code",
            &pkce,
        )
        .await
        .unwrap();
        assert_eq!(set.access_token, "at");
        assert_eq!(set.refresh_token.as_deref(), Some("rt"));

        let form = http.form_for("https://auth.example.com/token").unwrap();
        let m: std::collections::HashMap<_, _> = form.into_iter().collect();
        assert_eq!(m["grant_type"], "authorization_code");
        assert_eq!(m["code_verifier"], pkce.verifier());
        assert_eq!(m["resource"], "https://mcp.example.com/mcp");
        assert_eq!(m["redirect_uri"], "http://127.0.0.1:1/callback");
    }

    /// Slack's shape. Failing here — before the browser opens — is much better
    /// than failing at the token endpoint after the user has consented.
    #[tokio::test]
    async fn exchange_refuses_a_confidential_only_token_endpoint() {
        let mut m = md();
        m.token_endpoint_auth_methods_supported =
            TokenEndpointAuth::Listed(vec!["client_secret_post".into()]);
        let http = FakeHttp::default();
        let pkce = Pkce::from_verifier("v".repeat(43));
        let err = exchange_code(
            &http,
            &m,
            &public("c"),
            "http://127.0.0.1:1/callback",
            Some("r"),
            "code",
            &pkce,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("client secret"), "{err}");
        // The message names what the user can DO. It used to point at an
        // MCP-specific document, which is wrong for a crate that now serves
        // providers reached by issuer and static configuration too.
        assert!(err.contains("Register an app"), "{err}");
    }

    mod extra_authorize_params {
        use super::*;

        fn url_with(extra: &[(String, String)]) -> anyhow::Result<Url> {
            let pkce = Pkce::from_verifier("v".repeat(43));
            authorization_url_with(
                &md(),
                &AuthorizeParams {
                    client_id: "cid",
                    redirect_uri: "http://127.0.0.1:1/callback",
                    scopes: &["read".to_string()],
                    resource: None,
                    state: "st",
                    pkce: &pkce,
                },
                extra,
            )
        }

        #[test]
        fn a_providers_own_parameters_are_appended() {
            // Google issues no refresh token without access_type=offline.
            let url = url_with(&[
                ("access_type".into(), "offline".into()),
                ("prompt".into(), "consent".into()),
            ])
            .unwrap();
            let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(q["access_type"], "offline");
            assert_eq!(q["prompt"], "consent");
            // And the standard set still travels.
            assert_eq!(q["code_challenge_method"], "S256");
            assert_eq!(q["state"], "st");
        }

        /// Each name is written out, NOT iterated from
        /// `RESERVED_AUTHORIZE_PARAMS`.
        ///
        /// Deriving the expectation from the production constant made this test
        /// self-referential: deleting `state` from the list deleted its own test
        /// case, and the suite stayed green while a manifest could replace the
        /// CSRF nonce. A security expectation has to be stated independently of
        /// the thing it constrains.
        #[test]
        fn every_parameter_the_flow_owns_is_refused() {
            for reserved in [
                "response_type",
                "client_id",
                "redirect_uri",
                "state",
                "code_challenge",
                "code_challenge_method",
                "resource",
                "scope",
            ] {
                let err = url_with(&[(reserved.to_string(), "hijacked".into())])
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("set by the flow"), "{reserved}: {err}");
            }
        }

        /// What each of those would cost if it were overridable, so the list
        /// above cannot be trimmed without someone reading why.
        #[test]
        fn the_reserved_list_covers_every_parameter_that_could_subvert_the_flow() {
            for required in [
                // redirects the code to somewhere this process cannot receive it
                "redirect_uri",
                // replaces the CSRF nonce, so a foreign callback completes this flow
                "state",
                // replaces the PKCE binding, so the exchange is no longer proof
                "code_challenge",
                "code_challenge_method",
                // changes which client the grant is issued to
                "client_id",
                // changes the grant type out from under the exchange
                "response_type",
            ] {
                assert!(
                    RESERVED_AUTHORIZE_PARAMS.contains(&required),
                    "{required} must stay reserved"
                );
            }
        }

        #[test]
        fn a_reserved_name_is_refused_whatever_its_case() {
            // A case-sensitive check would be trivially bypassed.
            let err = url_with(&[("Redirect_URI".into(), "https://evil".into())])
                .unwrap_err()
                .to_string();
            assert!(err.contains("set by the flow"), "{err}");
        }

        #[test]
        fn no_extras_is_identical_to_the_plain_builder() {
            let pkce = Pkce::from_verifier("v".repeat(43));
            let params = AuthorizeParams {
                client_id: "cid",
                redirect_uri: "http://127.0.0.1:1/callback",
                scopes: &["read".to_string()],
                resource: None,
                state: "st",
                pkce: &pkce,
            };
            assert_eq!(
                authorization_url(&md(), &params).unwrap(),
                authorization_url_with(&md(), &params, &[]).unwrap()
            );
        }
    }

    mod revocation {
        use super::*;

        fn md_with_revocation() -> AuthorizationServerMetadata {
            let mut m = md();
            m.revocation_endpoint = Some("https://auth.example.com/revoke".into());
            m
        }

        #[tokio::test]
        async fn a_published_endpoint_is_called_with_the_token() {
            let http = FakeHttp::default().with_post(
                "https://auth.example.com/revoke",
                FakeHttp::json(200, serde_json::json!({})),
            );
            let revoked = revoke_token(
                &http,
                &md_with_revocation(),
                "cid",
                None,
                "rt",
                "refresh_token",
            )
            .await
            .unwrap();

            assert!(revoked);
            let form = http.last_form().expect("a revocation was posted");
            assert!(form.iter().any(|(k, v)| k == "token" && v == "rt"));
            assert!(
                form.iter()
                    .any(|(k, v)| k == "token_type_hint" && v == "refresh_token")
            );
        }

        #[tokio::test]
        async fn a_server_that_publishes_none_is_not_an_error() {
            // Most remote MCP servers publish no revocation endpoint. Nothing
            // was attempted and nothing is wrong.
            let http = FakeHttp::default();
            let revoked = revoke_token(&http, &md(), "cid", None, "rt", "refresh_token")
                .await
                .unwrap();
            assert!(!revoked);
            assert!(http.last_form().is_none(), "no request was made");
        }

        #[tokio::test]
        async fn a_confidential_client_authenticates_its_revocation() {
            let http = FakeHttp::default().with_post(
                "https://auth.example.com/revoke",
                FakeHttp::json(200, serde_json::json!({})),
            );
            let mut m = md_with_revocation();
            m.token_endpoint_auth_methods_supported = TokenEndpointAuth::Unspecified;
            revoke_token(&http, &m, "cid", Some("sec"), "rt", "refresh_token")
                .await
                .unwrap();
            assert_eq!(
                http.last_basic_auth().unwrap(),
                Some(("cid".into(), "sec".into()))
            );
        }

        #[tokio::test]
        async fn a_refusal_is_reported_rather_than_swallowed() {
            // The caller removes locally regardless, but it must be able to say
            // that the provider still holds the grant.
            let http = FakeHttp::default().with_post(
                "https://auth.example.com/revoke",
                FakeHttp::json(400, serde_json::json!({"error": "invalid_request"})),
            );
            let err = revoke_token(
                &http,
                &md_with_revocation(),
                "cid",
                None,
                "rt",
                "refresh_token",
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(err.contains("refused"), "{err}");
        }

        #[tokio::test]
        async fn a_plaintext_revocation_endpoint_is_refused() {
            let mut m = md();
            m.revocation_endpoint = Some("http://auth.example.com/revoke".into());
            let err = revoke_token(&FakeHttp::default(), &m, "cid", None, "rt", "refresh_token")
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("https"), "{err}");
        }
    }

    mod provider_resolution {
        use super::*;

        const AS_METADATA: &str =
            "https://accounts.example.com/.well-known/oauth-authorization-server";

        fn issuer_metadata(issuer: &str) -> serde_json::Value {
            serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": "https://accounts.example.com/authorize",
                "token_endpoint": "https://accounts.example.com/token",
                "scopes_supported": ["profile", "email"],
                "code_challenge_methods_supported": ["S256"],
            })
        }

        #[tokio::test]
        async fn an_issuer_resolves_without_protected_resource_metadata() {
            // Google publishes no RFC 9728 document; discovery starts from the
            // issuer instead.
            let issuer = Url::parse("https://accounts.example.com").unwrap();
            let http = FakeHttp::default().with_get(
                AS_METADATA,
                FakeHttp::json(200, issuer_metadata("https://accounts.example.com")),
            );

            let d = resolve_provider(&http, ProviderResolution::Issuer { url: &issuer })
                .await
                .unwrap();

            assert_eq!(
                d.metadata.token_endpoint,
                "https://accounts.example.com/token"
            );
            assert_eq!(
                d.resource, None,
                "an issuer has no RFC 8707 audience to bind to"
            );
            assert_eq!(d.resource_scopes, vec!["profile", "email"]);
        }

        #[tokio::test]
        async fn an_issuer_whose_metadata_names_someone_else_is_refused() {
            // RFC 8414 §3.3. Skipping this is how a misconfigured or hostile
            // host points a client at an authorization server it controls.
            let issuer = Url::parse("https://accounts.example.com").unwrap();
            let http = FakeHttp::default().with_get(
                AS_METADATA,
                FakeHttp::json(200, issuer_metadata("https://attacker.example")),
            );

            let err = resolve_provider(&http, ProviderResolution::Issuer { url: &issuer })
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("does not match"), "{err}");
        }

        #[tokio::test]
        async fn an_issuer_must_be_https() {
            let issuer = Url::parse("http://accounts.example.com").unwrap();
            let err = resolve_provider(
                &FakeHttp::default(),
                ProviderResolution::Issuer { url: &issuer },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(err.contains("https"), "{err}");
        }

        fn static_resolution<'a>(authorize: &'a Url, token: &'a Url) -> ProviderResolution<'a> {
            ProviderResolution::Static {
                issuer: "https://github.com",
                authorization_endpoint: authorize,
                token_endpoint: token,
                token_endpoint_auth_methods_supported: vec!["client_secret_post".into()],
                scopes_supported: vec!["repo".into()],
            }
        }

        #[tokio::test]
        async fn static_endpoints_need_no_document_at_all() {
            let authorize = Url::parse("https://github.com/login/oauth/authorize").unwrap();
            let token = Url::parse("https://github.com/login/oauth/access_token").unwrap();

            let d = resolve_provider(&FakeHttp::default(), static_resolution(&authorize, &token))
                .await
                .unwrap();

            assert_eq!(d.metadata.issuer, "https://github.com");
            assert_eq!(d.metadata.token_endpoint, token.as_str());
            assert_eq!(d.resource, None);
            assert_eq!(
                d.metadata.token_endpoint_auth_methods_supported,
                TokenEndpointAuth::Listed(vec!["client_secret_post".into()]),
                "a static provider states its method, since no document will"
            );
            assert!(
                d.metadata.supports_s256(),
                "omitted challenge methods must not block S256"
            );
        }

        #[tokio::test]
        async fn static_endpoints_must_still_be_https() {
            // The issuer-match check does not apply here — there is no third
            // party's claim to verify — but the transport requirement does.
            let authorize = Url::parse("http://github.com/login/oauth/authorize").unwrap();
            let token = Url::parse("https://github.com/login/oauth/access_token").unwrap();
            let err = resolve_provider(&FakeHttp::default(), static_resolution(&authorize, &token))
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("https"), "{err}");
        }

        #[tokio::test]
        async fn protected_resource_resolution_is_the_unchanged_path() {
            // Delegates to `discover`, whose candidate ordering is subtle and is
            // covered by the tests written against it directly. This asserts
            // only that routing through the enum changes nothing observable.
            let mcp = u("https://mcp.example.com/mcp");
            let http = as_metadata(FakeHttp::default().with_get(
                "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                FakeHttp::json(200, prm_json("https://mcp.example.com/mcp")),
            ));

            let direct = discover(&http, &mcp, None).await.unwrap();
            let viaenum = resolve_provider(
                &http,
                ProviderResolution::ProtectedResource {
                    url: &mcp,
                    metadata_hint: None,
                },
            )
            .await
            .unwrap();

            assert_eq!(direct, viaenum);
            assert_eq!(
                viaenum.resource.as_deref(),
                Some("https://mcp.example.com/mcp"),
                "and it still carries the RFC 8707 audience the other two lack"
            );
        }
    }

    /// The confidential-client table from the design, one case per row.
    mod client_authentication {
        use super::*;

        fn confidential(client_id: &str, secret: &str) -> ClientIdentity {
            ClientIdentity::PastedConfidential {
                client_id: client_id.to_string(),
                redirect_uri: "http://127.0.0.1:1/callback".to_string(),
                client_secret: secret.to_string(),
            }
        }

        fn with_methods(methods: TokenEndpointAuth) -> AuthorizationServerMetadata {
            let mut m = md();
            m.token_endpoint_auth_methods_supported = methods;
            m
        }

        fn token_ok() -> FakeHttp {
            FakeHttp::default().with_post(
                "https://auth.example.com/token",
                FakeHttp::json(
                    200,
                    serde_json::json!({"access_token": "at", "token_type": "Bearer"}),
                ),
            )
        }

        async fn exchange_with(
            http: &FakeHttp,
            metadata: &AuthorizationServerMetadata,
            identity: &ClientIdentity,
        ) -> anyhow::Result<TokenSet> {
            let pkce = Pkce::from_verifier("v".repeat(43));
            exchange_code(
                http,
                metadata,
                identity,
                "http://127.0.0.1:1/callback",
                None,
                "the-code",
                &pkce,
            )
            .await
        }

        #[tokio::test]
        async fn an_omitted_method_list_means_basic() {
            // RFC 8414 §2: absent defaults to client_secret_basic. NOT a public
            // client, and not a reason to guess.
            let http = token_ok();
            let md = with_methods(TokenEndpointAuth::Unspecified);
            exchange_with(&http, &md, &confidential("cid", "sec"))
                .await
                .unwrap();

            assert_eq!(
                http.last_basic_auth().unwrap(),
                Some(("cid".into(), "sec".into()))
            );
            let form = http.last_form().unwrap();
            assert!(
                !form.iter().any(|(k, _)| k == "client_id"),
                "RFC 6749 §2.3.1 forbids two client-authentication methods in one \
                 request, so client_id must leave the body when Basic is used: {form:?}"
            );
            assert!(!form.iter().any(|(k, _)| k == "client_secret"));
        }

        #[tokio::test]
        async fn basic_is_preferred_when_both_are_offered() {
            let http = token_ok();
            let md = with_methods(TokenEndpointAuth::Listed(vec![
                "client_secret_post".into(),
                "client_secret_basic".into(),
            ]));
            exchange_with(&http, &md, &confidential("cid", "sec"))
                .await
                .unwrap();
            assert!(http.last_basic_auth().unwrap().is_some());
        }

        #[tokio::test]
        async fn post_is_used_when_it_is_the_only_secret_method() {
            let http = token_ok();
            let md = with_methods(TokenEndpointAuth::Listed(vec!["client_secret_post".into()]));
            exchange_with(&http, &md, &confidential("cid", "sec"))
                .await
                .unwrap();

            assert_eq!(http.last_basic_auth().unwrap(), None);
            let form = http.last_form().unwrap();
            assert!(form.iter().any(|(k, v)| k == "client_secret" && v == "sec"));
            assert!(
                form.iter().any(|(k, _)| k == "client_id"),
                "client_id stays in the body when it is not carried by Basic"
            );
        }

        #[tokio::test]
        async fn a_public_only_server_given_a_secret_sends_no_client_authentication() {
            // The secret is inert here, not a reason to fail: the server said a
            // public client is acceptable and PKCE carries the proof.
            let http = token_ok();
            let md = with_methods(TokenEndpointAuth::Listed(vec!["none".into()]));
            exchange_with(&http, &md, &confidential("cid", "sec"))
                .await
                .unwrap();

            assert_eq!(http.last_basic_auth().unwrap(), None);
            let form = http.last_form().unwrap();
            assert!(!form.iter().any(|(k, _)| k == "client_secret"));
        }

        #[tokio::test]
        async fn an_explicitly_empty_list_is_refused_before_the_browser_opens() {
            // Distinct from an omitted field, which serde's default would have
            // flattened into the same empty vector.
            let http = token_ok();
            let md = with_methods(TokenEndpointAuth::Listed(vec![]));
            let err = exchange_with(&http, &md, &confidential("cid", "sec"))
                .await
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("has not said how a client may authenticate"),
                "{err}"
            );
        }

        #[tokio::test]
        async fn a_jwt_only_server_is_refused_rather_than_attempted() {
            let http = token_ok();
            let md = with_methods(TokenEndpointAuth::Listed(vec![
                "private_key_jwt".into(),
                "client_secret_jwt".into(),
            ]));
            let err = exchange_with(&http, &md, &confidential("cid", "sec"))
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("none of which Kunobi can perform"), "{err}");
        }

        #[tokio::test]
        async fn basic_credential_halves_are_form_encoded_per_rfc6749() {
            // This test previously asserted the pair reached the client
            // VERBATIM -- i.e. it asserted the bug. RFC 6749 §2.3.1 requires
            // each half to be form-encoded before the colon join and base64,
            // and skipping it is not cosmetic: a `:` in the secret splits the
            // credential in the wrong place, and `+` or `/` decode to different
            // bytes at the server. Both yield `invalid_client` with nothing
            // naming the cause.
            let http = token_ok();
            let md = with_methods(TokenEndpointAuth::Unspecified);
            exchange_with(&http, &md, &confidential("id:with:colons", "s3c/ret+=&"))
                .await
                .unwrap();

            assert_eq!(
                http.last_basic_auth().unwrap(),
                Some((
                    "id%3Awith%3Acolons".to_string(),
                    "s3c%2Fret%2B%3D%26".to_string()
                ))
            );
        }

        #[tokio::test]
        async fn ordinary_credentials_are_unchanged_by_the_encoding() {
            // The encoding must not disturb the common case.
            let http = token_ok();
            let md = with_methods(TokenEndpointAuth::Unspecified);
            exchange_with(&http, &md, &confidential("plain-client-id", "plainsecret"))
                .await
                .unwrap();
            assert_eq!(
                http.last_basic_auth().unwrap(),
                Some(("plain-client-id".into(), "plainsecret".into()))
            );
        }

        #[tokio::test]
        async fn a_confidential_refresh_authenticates_too() {
            // A refresh that dropped the secret would fail the moment the first
            // access token expired -- long after the user believed they were done.
            let http = FakeHttp::default().with_post(
                "https://auth.example.com/token",
                FakeHttp::json(
                    200,
                    serde_json::json!({"access_token": "at2", "token_type": "Bearer"}),
                ),
            );
            refresh_token(
                &http,
                &with_methods(TokenEndpointAuth::Unspecified),
                "cid",
                Some("sec"),
                None,
                "old-rt",
                &[],
            )
            .await
            .unwrap();
            assert_eq!(
                http.last_basic_auth().unwrap(),
                Some(("cid".into(), "sec".into()))
            );
        }

        #[test]
        fn a_secret_never_reaches_a_debug_line() {
            // ClientIdentity is embedded in caller-owned structs that derive
            // Debug, so the derive HERE is what a stray {:?} several frames away
            // would reach.
            let rendered = format!("{:?}", confidential("cid", "super-secret-value"));
            assert!(!rendered.contains("super-secret-value"), "{rendered}");
            assert!(rendered.contains("<redacted>"), "{rendered}");
            assert!(
                rendered.contains("cid"),
                "the client id is public and stays legible"
            );
        }
    }

    #[tokio::test]
    async fn refresh_carries_forward_a_non_rotated_refresh_token() {
        let http = FakeHttp::default().with_post(
            "https://auth.example.com/token",
            FakeHttp::json(
                200,
                serde_json::json!({"access_token": "at2", "expires_in": 60}),
            ),
        );
        let set = refresh_token(&http, &md(), "cid", None, Some("res"), "old-rt", &[])
            .await
            .unwrap();
        assert_eq!(set.access_token, "at2");
        assert_eq!(
            set.refresh_token.as_deref(),
            Some("old-rt"),
            "a server that does not rotate must not leave us without a refresh token"
        );
    }

    #[tokio::test]
    async fn refresh_adopts_a_rotated_refresh_token() {
        let http = FakeHttp::default().with_post(
            "https://auth.example.com/token",
            FakeHttp::json(
                200,
                serde_json::json!({"access_token": "at2", "refresh_token": "new-rt"}),
            ),
        );
        let set = refresh_token(&http, &md(), "cid", None, Some("res"), "old-rt", &[])
            .await
            .unwrap();
        assert_eq!(set.refresh_token.as_deref(), Some("new-rt"));
    }

    #[tokio::test]
    async fn refresh_surfaces_invalid_grant() {
        let http = FakeHttp::default().with_post(
            "https://auth.example.com/token",
            FakeHttp::json(400, serde_json::json!({"error": "invalid_grant"})),
        );
        let err = refresh_token(&http, &md(), "cid", None, Some("res"), "dead", &[])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid_grant"), "{err}");
    }

    /// Minimisation is the whole point: an empty request must NOT expand into
    /// the server's full capability list.
    #[test]
    fn minimal_scopes_never_expands_to_everything_supported() {
        let supported = vec![
            "read".to_string(),
            "write".to_string(),
            "developer.billing.write".to_string(),
        ];
        assert!(minimal_scopes(&[], &supported).is_empty());
        assert_eq!(
            minimal_scopes(&["read".into(), " read ".into(), "".into()], &supported),
            vec!["read".to_string()]
        );
    }
}

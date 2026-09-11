//! Locating the authorization server for a remote MCP endpoint.
//!
//! Two RFCs and one ordering trap:
//!
//! * **RFC 9728** — the MCP server publishes *protected resource metadata*
//!   naming its authorization server(s). Reachable either from the
//!   `WWW-Authenticate` challenge on a 401 (`resource_metadata="…"`) or by
//!   probing `/.well-known/oauth-protected-resource`.
//! * **RFC 8414** — the authorization server publishes its own metadata
//!   (authorization/token/registration endpoints) at a `.well-known` URL
//!   derived from the issuer.
//!
//! The trap is the derivation for an issuer that has a path component. RFC 8414
//! §3.1 inserts the well-known segment *before* the path
//! (`https://h/.well-known/oauth-authorization-server/tenant`); OpenID Connect
//! Discovery appends it (`https://h/tenant/.well-known/openid-configuration`).
//! An implementation that tries the appending form first concludes that a
//! fully standard server is non-compliant — Stripe is the worked example.
//! [`authorization_server_metadata_urls`] therefore emits the RFC 8414
//! path-insertion form first.

use serde::Deserialize as _;
use url::Url;

/// RFC 9728 protected-resource metadata, reduced to the fields we act on.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ProtectedResourceMetadata {
    /// Canonical resource identifier. Sent as RFC 8707 `resource` on the
    /// authorization and token requests so the issued token is audience-bound.
    pub resource: String,
    /// Authorization servers that can issue tokens for this resource.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// Scopes the resource understands. Used to build a *minimal* request, not
    /// to request everything — see [`crate::oauth::flow::minimal_scopes`].
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// RFC 8414 authorization-server metadata, reduced to the fields we act on.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// RFC 7591 dynamic client registration. Absent on the "pre-registered
    /// public client" category (X), which is why a pasted `client_id` is a
    /// first-class path and not a fallback.
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    #[serde(deserialize_with = "de_token_endpoint_auth")]
    pub token_endpoint_auth_methods_supported: TokenEndpointAuth,
    /// RFC 7009 revocation endpoint, when the server publishes one.
    ///
    /// Most remote MCP servers do not; Google does. A disconnect that only
    /// removes the local copy leaves the grant live at the provider, which is
    /// not what "disconnect" means to a user looking at their authorized-apps
    /// list.
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
}

/// What a server said about token-endpoint client authentication.
///
/// The distinction between "did not say" and "said nothing" is load-bearing and
/// `#[serde(default)]` on a `Vec` erases it: both arrive as an empty vector.
///
/// RFC 8414 §2 gives an ABSENT field the default `client_secret_basic` — so a
/// server that omits it is asking for Basic, not permitting a public client. An
/// explicitly EMPTY list is different: the server has said, positively, that it
/// supports no method at all. Guessing Basic there would send the user through a
/// consent whose redemption cannot work.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
#[serde(untagged)]
pub enum TokenEndpointAuth {
    /// The field was absent.
    #[default]
    Unspecified,
    /// The server listed methods — possibly none.
    Listed(Vec<String>),
}

impl TokenEndpointAuth {
    /// The listed methods, or empty when the field was absent. For display and
    /// error text only — a decision must use [`AuthorizationServerMetadata::select_client_auth`],
    /// which distinguishes the two cases.
    pub fn listed(&self) -> &[String] {
        match self {
            Self::Unspecified => &[],
            Self::Listed(m) => m,
        }
    }
}

fn de_token_endpoint_auth<'de, D>(d: D) -> Result<TokenEndpointAuth, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<Vec<String>>::deserialize(d)?;
    Ok(match v {
        None => TokenEndpointAuth::Unspecified,
        Some(m) => TokenEndpointAuth::Listed(m),
    })
}

/// How to authenticate this client at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// No client authentication — a public client proving itself with PKCE.
    None,
    /// HTTP Basic. RFC 6749 §2.3.1 requires servers to support it, so it is
    /// preferred wherever both are offered.
    Basic,
    /// Credentials in the form body.
    Post,
}

impl AuthorizationServerMetadata {
    /// Whether the server advertises S256. An empty list means the field was
    /// omitted, which RFC 8414 leaves to out-of-band knowledge; MCP requires
    /// S256, so an omission is treated as "supported" rather than as a reason
    /// to refuse. An explicit list that omits S256 is a refusal.
    pub fn supports_s256(&self) -> bool {
        self.code_challenge_methods_supported.is_empty()
            || self
                .code_challenge_methods_supported
                .iter()
                .any(|m| m == "S256")
    }

    /// Whether the token endpoint accepts an unauthenticated (public) client.
    ///
    /// An omitted list defaults to `client_secret_basic` per RFC 8414 §2, so an
    /// omission is **not** permission for a public client. Slack is the case
    /// this distinguishes: it advertises `client_secret_post` only, which is
    /// exactly why it cannot be completed without a secret.
    pub fn allows_public_client(&self) -> bool {
        matches!(
            &self.token_endpoint_auth_methods_supported,
            TokenEndpointAuth::Listed(m) if m.iter().any(|m| m == "none")
        )
    }

    /// Which client-authentication method to use with a supplied secret.
    ///
    /// See [`TokenEndpointAuth`] for why an omitted list and an explicitly empty
    /// one must not be treated the same.
    pub fn select_client_auth(&self) -> anyhow::Result<ClientAuthMethod> {
        match &self.token_endpoint_auth_methods_supported {
            // RFC 8414 §2: absent means `client_secret_basic`.
            TokenEndpointAuth::Unspecified => Ok(ClientAuthMethod::Basic),
            TokenEndpointAuth::Listed(m) if m.is_empty() => anyhow::bail!(
                "{} published an empty token_endpoint_auth_methods_supported, so it has \
                 not said how a client may authenticate. Refusing before opening a browser \
                 rather than guessing.",
                self.issuer
            ),
            TokenEndpointAuth::Listed(m) => {
                // RFC 6749 §2.3.1 says a server MUST support Basic, so prefer it
                // where both are offered.
                if m.iter().any(|x| x == "client_secret_basic") {
                    Ok(ClientAuthMethod::Basic)
                } else if m.iter().any(|x| x == "client_secret_post") {
                    Ok(ClientAuthMethod::Post)
                } else if m.iter().any(|x| x == "none") {
                    // A public client that was nonetheless given a secret: send
                    // no client authentication. The secret is inert, not a
                    // reason to fail.
                    Ok(ClientAuthMethod::None)
                } else {
                    anyhow::bail!(
                        "{} requires token-endpoint client authentication by {:?}, none of \
                         which Kunobi can perform. Refusing before opening a browser, so the \
                         user is not sent through a consent that cannot be redeemed.",
                        self.issuer,
                        m
                    )
                }
            }
        }
    }

    pub fn supports_refresh_token(&self) -> bool {
        self.grant_types_supported.is_empty()
            || self
                .grant_types_supported
                .iter()
                .any(|g| g == "refresh_token")
    }
}

/// Candidate URLs for RFC 9728 protected-resource metadata, most specific first.
///
/// Path-insertion first (`/.well-known/oauth-protected-resource/mcp` for
/// `https://h/mcp`), then the root form, which is what a server that hosts one
/// MCP endpoint at a subpath usually serves.
pub fn protected_resource_metadata_urls(resource: &Url) -> Vec<Url> {
    well_known_candidates(resource, &["oauth-protected-resource"], false)
}

/// Candidate URLs for RFC 8414 authorization-server metadata, in the order the
/// MCP authorization spec requires.
///
/// For an issuer with a path (`https://h/tenant`):
/// 1. `https://h/.well-known/oauth-authorization-server/tenant` — RFC 8414 §3.1
/// 2. `https://h/.well-known/openid-configuration/tenant` — OIDC, path insertion
/// 3. `https://h/tenant/.well-known/openid-configuration` — OIDC, path appending
/// 4. `https://h/.well-known/oauth-authorization-server` — root fallback
///
/// For a path-less issuer, only the two root forms exist.
pub fn authorization_server_metadata_urls(issuer: &Url) -> Vec<Url> {
    well_known_candidates(
        issuer,
        &["oauth-authorization-server", "openid-configuration"],
        true,
    )
}

/// Shared candidate builder.
///
/// `oidc_appending` adds the OpenID-Connect path-appending form, which is
/// meaningful for an authorization server and not for a protected resource.
fn well_known_candidates(base: &Url, resources: &[&str], oidc_appending: bool) -> Vec<Url> {
    let mut out: Vec<Url> = Vec::new();
    let mut push = |path: String| {
        let mut u = base.clone();
        u.set_query(None);
        u.set_fragment(None);
        u.set_path(&path);
        if !out.contains(&u) {
            out.push(u);
        }
    };

    let trimmed = base.path().trim_matches('/').to_string();
    if trimmed.is_empty() {
        for r in resources {
            push(format!("/.well-known/{r}"));
        }
        return out;
    }

    // 1. RFC 8414 / RFC 9728 path insertion, in the caller's resource order.
    for r in resources {
        push(format!("/.well-known/{r}/{trimmed}"));
    }
    // 2. OIDC path appending, only where an OIDC document can live.
    if oidc_appending {
        push(format!("/{trimmed}/.well-known/openid-configuration"));
    }
    // 3. Root fallback, for servers that publish one document for the host.
    for r in resources {
        push(format!("/.well-known/{r}"));
    }
    out
}

/// Extract `resource_metadata="…"` from a `WWW-Authenticate: Bearer …` header.
///
/// Returns `None` for a challenge that is not `Bearer`, or that omits the
/// parameter. Deliberately tolerant of parameter order, spacing and case in the
/// scheme and parameter name, because real servers vary on all three.
pub fn parse_www_authenticate_resource_metadata(header: &str) -> Option<Url> {
    let rest = header.trim();
    let (scheme, params) = rest.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    for part in split_auth_params(params) {
        let (k, v) = part.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("resource_metadata") {
            let v = v.trim().trim_matches('"');
            return Url::parse(v).ok();
        }
    }
    None
}

/// Split `a="x,y", b="z"` on commas that are not inside a quoted string.
fn split_auth_params(params: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    for (i, c) in params.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(params[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(params[start..].trim());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn paths(urls: &[Url]) -> Vec<String> {
        urls.iter().map(|x| x.path().to_string()).collect()
    }

    /// The ordering finding from the live probe: path insertion BEFORE the
    /// appending form. Getting this backwards makes a compliant server (Stripe)
    /// look non-compliant, and the failure mode is a confusing 404 rather than
    /// an error that names the cause.
    #[test]
    fn authorization_server_tries_rfc8414_path_insertion_before_oidc_appending() {
        let got = paths(&authorization_server_metadata_urls(&u(
            "https://auth.example.com/v1/tenant",
        )));
        assert_eq!(
            got,
            vec![
                "/.well-known/oauth-authorization-server/v1/tenant",
                "/.well-known/openid-configuration/v1/tenant",
                "/v1/tenant/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration",
            ]
        );
        let insertion = got
            .iter()
            .position(|p| p == "/.well-known/oauth-authorization-server/v1/tenant")
            .unwrap();
        let appending = got
            .iter()
            .position(|p| p == "/v1/tenant/.well-known/openid-configuration")
            .unwrap();
        assert!(insertion < appending, "path insertion must be tried first");
    }

    #[test]
    fn authorization_server_pathless_issuer_has_only_root_forms() {
        assert_eq!(
            paths(&authorization_server_metadata_urls(&u(
                "https://auth.example.com"
            ))),
            vec![
                "/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration",
            ]
        );
    }

    #[test]
    fn authorization_server_candidates_drop_query_and_fragment() {
        let got = authorization_server_metadata_urls(&u("https://a.example/t?x=1#f"));
        assert!(
            got.iter()
                .all(|x| x.query().is_none() && x.fragment().is_none())
        );
        assert_eq!(
            got[0].as_str(),
            "https://a.example/.well-known/oauth-authorization-server/t"
        );
    }

    #[test]
    fn protected_resource_candidates_are_insertion_then_root() {
        assert_eq!(
            paths(&protected_resource_metadata_urls(&u(
                "https://mcp.example.com/mcp"
            ))),
            vec![
                "/.well-known/oauth-protected-resource/mcp",
                "/.well-known/oauth-protected-resource",
            ]
        );
    }

    #[test]
    fn candidates_are_deduplicated() {
        // A trailing slash trims to the same non-empty path, and the root
        // fallback must not be emitted twice for a single-segment resource.
        let got = protected_resource_metadata_urls(&u("https://mcp.example.com/"));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path(), "/.well-known/oauth-protected-resource");
    }

    #[test]
    fn parses_resource_metadata_from_challenge() {
        let h = r#"Bearer error="invalid_token", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource""#;
        assert_eq!(
            parse_www_authenticate_resource_metadata(h)
                .unwrap()
                .as_str(),
            "https://mcp.example.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn parses_resource_metadata_regardless_of_case_and_order() {
        let h = r#"bearer Resource_Metadata="https://a.example/.well-known/oauth-protected-resource", error="x""#;
        assert!(parse_www_authenticate_resource_metadata(h).is_some());
    }

    #[test]
    fn ignores_non_bearer_and_missing_parameter() {
        assert!(parse_www_authenticate_resource_metadata(r#"Basic realm="x""#).is_none());
        assert!(
            parse_www_authenticate_resource_metadata(r#"Bearer error="invalid_token""#).is_none()
        );
        assert!(parse_www_authenticate_resource_metadata("Bearer").is_none());
    }

    /// A comma inside a quoted value must not split the parameter list, or the
    /// URL is truncated at the comma and discovery silently falls back to
    /// probing.
    #[test]
    fn quoted_commas_do_not_split_parameters() {
        let h = r#"Bearer scope="a,b", resource_metadata="https://a.example/.well-known/oauth-protected-resource""#;
        assert_eq!(
            parse_www_authenticate_resource_metadata(h).unwrap().path(),
            "/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn public_client_is_not_assumed_when_the_server_omits_the_list() {
        // RFC 8414 §2 defaults an omitted list to client_secret_basic. Slack is
        // the reason this matters: assuming `none` would produce a flow that
        // fails only at the token endpoint, after the user has consented.
        let m = AuthorizationServerMetadata {
            issuer: "https://a.example".into(),
            authorization_endpoint: "https://a.example/authorize".into(),
            token_endpoint: "https://a.example/token".into(),
            registration_endpoint: None,
            scopes_supported: vec![],
            code_challenge_methods_supported: vec![],
            token_endpoint_auth_methods_supported: TokenEndpointAuth::Listed(vec![]),
            grant_types_supported: vec![],
            revocation_endpoint: None,
        };
        assert!(!m.allows_public_client());
        assert!(
            m.supports_s256(),
            "omitted challenge methods must not block S256"
        );

        let slack = AuthorizationServerMetadata {
            token_endpoint_auth_methods_supported: TokenEndpointAuth::Listed(vec![
                "client_secret_post".into(),
            ]),
            ..m.clone()
        };
        assert!(!slack.allows_public_client());

        let public = AuthorizationServerMetadata {
            token_endpoint_auth_methods_supported: TokenEndpointAuth::Listed(vec!["none".into()]),
            ..m.clone()
        };
        assert!(public.allows_public_client());
    }

    #[test]
    fn explicit_challenge_methods_without_s256_are_refused() {
        let m = AuthorizationServerMetadata {
            issuer: "https://a.example".into(),
            authorization_endpoint: "https://a.example/authorize".into(),
            token_endpoint: "https://a.example/token".into(),
            registration_endpoint: None,
            scopes_supported: vec![],
            code_challenge_methods_supported: vec!["plain".into()],
            token_endpoint_auth_methods_supported: TokenEndpointAuth::Listed(vec!["none".into()]),
            grant_types_supported: vec![],
            revocation_endpoint: None,
        };
        assert!(!m.supports_s256());
    }

    #[test]
    fn metadata_deserialises_with_unknown_and_missing_fields() {
        let m: AuthorizationServerMetadata = serde_json::from_str(
            r#"{"issuer":"https://a.example","authorization_endpoint":"https://a.example/a",
                "token_endpoint":"https://a.example/t","something_new":42}"#,
        )
        .unwrap();
        assert!(m.registration_endpoint.is_none());
        assert!(m.scopes_supported.is_empty());

        let p: ProtectedResourceMetadata =
            serde_json::from_str(r#"{"resource":"https://mcp.example.com/mcp"}"#).unwrap();
        assert!(p.authorization_servers.is_empty());
    }
}

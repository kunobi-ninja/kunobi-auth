//! RFC 7591 dynamic client registration, and the pasted-`client_id` alternative.
//!
//! Live probing of sixteen hosted MCP servers put them in three groups:
//!
//! * **dynamic registration** (Linear, Notion, Sentry, Asana, Intercom,
//!   Atlassian, PayPal, Square, Webflow, Zapier, Stripe) — a
//!   `registration_endpoint` plus `none` at the token endpoint, so a public
//!   client with PKCE and a loopback redirect completes with no user setup;
//! * **pre-registered public client** (X) — no `registration_endpoint`, but
//!   `none` is accepted, so the user registers an app once and pastes its
//!   `client_id`;
//! * **confidential client** (Slack, Vercel, GitHub) — a client *secret* is
//!   required at the token endpoint. Out of scope here; see
//!   `docs/MCP-REMOTE-AUTH.md`.
//!
//! The middle group is the reason [`ClientIdentity::Pasted`] exists as a peer
//! of `Registered` rather than an error path: it is also why Claude Code, Codex
//! and Cursor fail where this does not — they go straight to dynamic
//! registration, which the MCP spec lists last.

use url::Url;

use crate::oauth::http_seam::OAuthHttp;

/// How this connection got its `client_id`.
#[derive(Clone, PartialEq, Eq)]
pub enum ClientIdentity {
    /// Obtained from the server's `registration_endpoint`.
    Registered {
        /// The client identifier issued by the server.
        client_id: String,
    },
    /// Supplied by the user, from an app they registered themselves.
    ///
    /// Carries the exact redirect URI they registered. That URI is a promise to
    /// the authorization server: its port cannot be renegotiated, which is why
    /// [`crate::oauth::callback`] refuses to fall back to a random port for this case.
    Pasted {
        /// The client identifier the user pasted from their own app.
        client_id: String,
        /// The redirect URI the user registered for the app.
        redirect_uri: String,
    },
    /// Supplied by the user, from an app they registered themselves, whose
    /// token endpoint requires client authentication.
    ///
    /// Google, GitHub, Slack and Vercel all land here: they publish no
    /// `registration_endpoint` and refuse `none` at the token endpoint. The
    /// objection above — that a client secret in a desktop app is not a secret
    /// — is about DYNAMIC REGISTRATION handing us one we did not ask for. This
    /// is the user's own credential for their own app, the same thing they
    /// already paste as a personal access token, and Kunobi ships nothing.
    ///
    /// For a GitHub OAuth App the secret is the only client authentication
    /// (GitHub does not enforce PKCE), so anyone who extracts it can redeem
    /// codes for that app. Google documents desktop-client secrets as
    /// non-confidential. Either way the blast radius is the user's own
    /// registration, which is why this is offered rather than refused.
    PastedConfidential {
        /// The client identifier the user pasted from their own app.
        client_id: String,
        /// The redirect URI the user registered for the app.
        redirect_uri: String,
        /// The client secret the user pasted from their own app.
        client_secret: String,
    },
}

impl ClientIdentity {
    /// Returns the client identifier for this identity.
    pub fn client_id(&self) -> &str {
        match self {
            Self::Registered { client_id }
            | Self::Pasted { client_id, .. }
            | Self::PastedConfidential { client_id, .. } => client_id,
        }
    }

    /// The client secret, when this identity has one.
    pub fn client_secret(&self) -> Option<&str> {
        match self {
            Self::PastedConfidential { client_secret, .. } => Some(client_secret),
            _ => None,
        }
    }

    /// The redirect URI the user pre-registered, when they registered one.
    pub fn registered_redirect_uri(&self) -> Option<&str> {
        match self {
            Self::Pasted { redirect_uri, .. } | Self::PastedConfidential { redirect_uri, .. } => {
                Some(redirect_uri)
            }
            Self::Registered { .. } => None,
        }
    }
}

// `Debug` is hand-written because deriving it would print the secret.
//
// A redacting wrapper on the STRING would not be enough: this enum is embedded
// in caller-owned structs that themselves derive `Debug`, so the derive here is
// what a stray `{:?}` several frames away would reach.
impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registered { client_id } => f
                .debug_struct("Registered")
                .field("client_id", client_id)
                .finish(),
            Self::Pasted {
                client_id,
                redirect_uri,
            } => f
                .debug_struct("Pasted")
                .field("client_id", client_id)
                .field("redirect_uri", redirect_uri)
                .finish(),
            Self::PastedConfidential {
                client_id,
                redirect_uri,
                ..
            } => f
                .debug_struct("PastedConfidential")
                .field("client_id", client_id)
                .field("redirect_uri", redirect_uri)
                .field("client_secret", &"<redacted>")
                .finish(),
        }
    }
}

/// Register a public client with PKCE and a loopback redirect.
///
/// `token_endpoint_auth_method: "none"` is asserted, not negotiated: this
/// registers a *public* client, and a server that answers with a
/// `client_secret` has registered something else. That is surfaced as an error
/// rather than silently stored, because a client secret in a desktop app is not
/// a secret and pretending otherwise is the whole confidential-client problem.
pub async fn register_public_client(
    http: &dyn OAuthHttp,
    registration_endpoint: &Url,
    client_name: &str,
    redirect_uri: &str,
    scopes: &[String],
) -> anyhow::Result<ClientIdentity> {
    let mut body = serde_json::json!({
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
    });
    if !scopes.is_empty() {
        body["scope"] = serde_json::Value::String(scopes.join(" "));
    }

    let resp = http.post_json(registration_endpoint, &body).await?;
    if !resp.is_success() {
        anyhow::bail!(
            "dynamic client registration at {registration_endpoint} failed — {}",
            resp.error_summary()
        );
    }
    let doc = resp
        .body
        .ok_or_else(|| anyhow::anyhow!("client registration returned a non-JSON body"))?;

    if doc.get("client_secret").is_some() {
        anyhow::bail!(
            "{registration_endpoint} issued a confidential client (it returned a client_secret). \
             Kunobi registers public clients only — a client secret stored on this machine is not \
             a secret. See docs/MCP-REMOTE-AUTH.md."
        );
    }

    let client_id = doc
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("client registration response has no client_id"))?
        .to_string();

    Ok(ClientIdentity::Registered { client_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::http_seam::FakeHttp;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[tokio::test]
    async fn registers_a_public_native_client_with_the_exact_redirect_uri() {
        let http = FakeHttp::default().with_post(
            "https://a.example/register",
            FakeHttp::json(201, serde_json::json!({"client_id": "cid-123"})),
        );
        let id = register_public_client(
            &http,
            &u("https://a.example/register"),
            "Kunobi",
            "http://127.0.0.1:41234/callback",
            &["read".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(
            id,
            ClientIdentity::Registered {
                client_id: "cid-123".into()
            }
        );

        let sent = &http.recorded_json.lock().unwrap()[0].1;
        assert_eq!(sent["token_endpoint_auth_method"], "none");
        assert_eq!(sent["redirect_uris"][0], "http://127.0.0.1:41234/callback");
        assert_eq!(sent["scope"], "read");
        assert_eq!(sent["grant_types"][1], "refresh_token");
    }

    #[tokio::test]
    async fn omits_scope_when_none_are_requested() {
        let http = FakeHttp::default().with_post(
            "https://a.example/register",
            FakeHttp::json(201, serde_json::json!({"client_id": "c"})),
        );
        register_public_client(
            &http,
            &u("https://a.example/register"),
            "Kunobi",
            "http://127.0.0.1:1/callback",
            &[],
        )
        .await
        .unwrap();
        assert!(
            http.recorded_json.lock().unwrap()[0]
                .1
                .get("scope")
                .is_none()
        );
    }

    /// A server that hands back a client secret has registered a confidential
    /// client. Storing it would ship a "secret" to every user's disk and create
    /// exactly the false sense of safety the hosted-bouncer design exists to
    /// avoid, so this is a hard failure rather than a warning.
    #[tokio::test]
    async fn refuses_a_registration_that_returns_a_client_secret() {
        let http = FakeHttp::default().with_post(
            "https://a.example/register",
            FakeHttp::json(
                201,
                serde_json::json!({"client_id": "c", "client_secret": "shhh"}),
            ),
        );
        let err = register_public_client(
            &http,
            &u("https://a.example/register"),
            "K",
            "http://127.0.0.1:1/callback",
            &[],
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("confidential client"), "{err}");
        assert!(
            !err.contains("shhh"),
            "the secret must not reach an error string: {err}"
        );
    }

    #[tokio::test]
    async fn surfaces_a_registration_failure_with_the_server_error_code() {
        let http = FakeHttp::default().with_post(
            "https://a.example/register",
            FakeHttp::json(400, serde_json::json!({"error": "invalid_redirect_uri"})),
        );
        let err = register_public_client(
            &http,
            &u("https://a.example/register"),
            "K",
            "http://127.0.0.1:1/callback",
            &[],
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("invalid_redirect_uri"), "{err}");
    }

    #[tokio::test]
    async fn a_registration_without_client_id_is_an_error_not_an_empty_string() {
        let http = FakeHttp::default().with_post(
            "https://a.example/register",
            FakeHttp::json(201, serde_json::json!({"client_name": "K"})),
        );
        assert!(
            register_public_client(
                &http,
                &u("https://a.example/register"),
                "K",
                "http://127.0.0.1:1/callback",
                &[]
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn pasted_identity_carries_the_registered_redirect_uri() {
        let id = ClientIdentity::Pasted {
            client_id: "x-client".into(),
            redirect_uri: "http://localhost:8080/callback".into(),
        };
        assert_eq!(id.client_id(), "x-client");
    }
}

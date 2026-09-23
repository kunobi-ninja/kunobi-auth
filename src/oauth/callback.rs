//! The RFC 8252 loopback redirect listener.
//!
//! # Why the port is sometimes non-negotiable
//!
//! For a dynamically registered client we choose the redirect URI, so any free
//! port works and a collision can be resolved by picking another. For a
//! **pre-registered** client (X, and every server with no
//! `registration_endpoint`) the redirect URI was fixed by the user when they
//! created the app, and an authorization server rejects anything else. Silently
//! moving to a different port there produces `invalid_redirect_uri` *after* the
//! browser has opened — an error the user cannot act on, because nothing tells
//! them the port changed.
//!
//! So [`PortPolicy`] makes the difference explicit and the failure loud. The
//! same distinction is added to `auth::acquire_oauth_port` for Kunobi's own
//! sign-in flow, which had an unconditional random-port fallback.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Whether the loopback port may change if it is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortPolicy {
    /// The redirect URI is ours to choose: fall back to an OS-assigned port.
    Negotiable,
    /// The redirect URI is pre-registered: this exact port or nothing.
    Fixed,
}

/// The error codes RFC 6749 §4.1.2.1 defines for an authorization response.
///
/// An allowlist, for the same reason `JsonResponse::error_summary` uses one:
/// anything else is a value the server chose, and passing it through makes the
/// error text an arbitrary-string channel into a log line.
const AUTHORIZATION_ERROR_CODES: &[&str] = &[
    "invalid_request",
    "unauthorized_client",
    "access_denied",
    "unsupported_response_type",
    "invalid_scope",
    "server_error",
    "temporarily_unavailable",
];

/// A bound loopback listener waiting for the authorization redirect.
#[derive(Debug)]
pub struct CallbackListener {
    listener: TcpListener,
    redirect_uri: String,
}

/// What the authorization server sent back.
#[derive(Clone, PartialEq, Eq)]
pub struct CallbackResult {
    /// The authorization code to redeem at the token endpoint.
    pub code: String,
    /// The state value echoed back with the code.
    pub state: String,
}

// Hand-written: an authorization code is single-use but it IS a credential
// until it is redeemed, and this type travels through error paths where a
// stray `{:?}` would print it.
impl std::fmt::Debug for CallbackResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackResult")
            .field("code", &"<redacted>")
            .field("state", &self.state)
            .finish()
    }
}

impl CallbackListener {
    /// Bind the callback listener.
    ///
    /// `preferred_port` of `0` with [`PortPolicy::Negotiable`] asks the OS for
    /// any free port. With [`PortPolicy::Fixed`], a busy port is an error that
    /// names the port, because the caller cannot substitute another.
    pub async fn bind(preferred_port: u16, policy: PortPolicy, path: &str) -> anyhow::Result<Self> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, preferred_port));
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) if policy == PortPolicy::Negotiable && preferred_port != 0 => {
                tracing::warn!(
                    port = preferred_port,
                    "OAuth callback port busy, falling back to an OS-assigned port: {e}"
                );
                TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?
            }
            Err(e) => {
                anyhow::bail!(
                    "cannot bind the OAuth callback on 127.0.0.1:{preferred_port}: {e}. \
                     This connection uses a pre-registered redirect URI, so the port cannot be \
                     changed — free the port and retry, or re-register the app on a free port."
                )
            }
        };
        let port = listener.local_addr()?.port();
        Ok(Self {
            listener,
            redirect_uri: format!("http://127.0.0.1:{port}{path}"),
        })
    }

    /// The redirect URI to send to the authorization server. Always reflects the
    /// port actually bound, never the requested one.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// The local port the listener is bound to.
    pub fn port(&self) -> u16 {
        self.listener
            .local_addr()
            .map(|a| a.port())
            .unwrap_or_default()
    }

    /// Wait for the redirect, validate `state`, and return the code.
    ///
    /// Loops rather than accepting once: a browser (or a port scanner, or the
    /// OS's own connectivity probe) will happily open a connection that carries
    /// no code, and treating the first connection as the answer makes the flow
    /// fail intermittently for reasons the user cannot see. Bounded by
    /// `timeout` overall.
    pub async fn wait_for_code(
        self,
        expected_state: &str,
        timeout: Duration,
    ) -> anyhow::Result<CallbackResult> {
        tokio::time::timeout(timeout, self.accept_loop(expected_state))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "timed out after {}s waiting for the authorization redirect on {}",
                    timeout.as_secs(),
                    self.redirect_uri
                )
            })?
    }

    async fn accept_loop(&self, expected_state: &str) -> anyhow::Result<CallbackResult> {
        loop {
            let (mut stream, _peer) = self.listener.accept().await?;
            let mut buf = vec![0u8; 8192];
            let n = match stream.read(&mut buf).await {
                Ok(0) | Err(_) => continue,
                Ok(n) => n,
            };
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let Some(target) = request_target(&request) else {
                let _ = respond(&mut stream, 400, "Bad request.").await;
                continue;
            };

            match parse_callback_query(target, expected_state) {
                Ok(Some(result)) => {
                    let _ = respond(
                        &mut stream,
                        200,
                        "Kunobi received the authorization response. You can close this tab.",
                    )
                    .await;
                    return Ok(result);
                }
                // A connection that is not the redirect (favicon, probe): ignore.
                Ok(None) => {
                    let _ = respond(&mut stream, 404, "Not the callback.").await;
                }
                Err(e) => {
                    let _ =
                        respond(&mut stream, 400, "Authorization failed. Return to Kunobi.").await;
                    return Err(e);
                }
            }
        }
    }
}

/// Extract the request target from an HTTP/1.1 request line.
fn request_target(request: &str) -> Option<&str> {
    let line = request.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    if method != "GET" {
        return None;
    }
    parts.next()
}

/// Interpret the redirect's query string.
///
/// `Ok(None)` means "this was not the redirect"; `Err` means it was and it
/// failed. Conflating the two makes a `state` mismatch look like a stray
/// connection and hangs the flow until the timeout.
pub fn parse_callback_query(
    target: &str,
    expected_state: &str,
) -> anyhow::Result<Option<CallbackResult>> {
    let base = url::Url::parse("http://127.0.0.1")?;
    let url = base.join(target)?;
    let params: std::collections::HashMap<String, String> =
        url.query_pairs().into_owned().collect();

    // `state` is checked FIRST, even on an error callback.
    //
    // An error arm that reported before validating state let anyone who could
    // reach this loopback port produce a chosen error message — and end a flow
    // they had no part in. The CSRF guard is not only for the success path.
    if let Some(state) = params.get("state") {
        if !crate::oauth::pkce::state_matches(expected_state, state) {
            anyhow::bail!(
                "the authorization response carried the wrong state parameter; the request was \
                 discarded. Start the connection again."
            );
        }
    } else if params.contains_key("error") {
        // An error with no state cannot be attributed to this flow at all.
        return Ok(None);
    }

    if let Some(err) = params.get("error") {
        // Only the RFC 6749 §4.1.2.1 code, and `error_description` never:
        // it is free text the server chose, it routinely echoes request
        // parameters, and this string is logged and shown to the user.
        let code = AUTHORIZATION_ERROR_CODES
            .iter()
            .find(|known| *known == err)
            .copied()
            .unwrap_or("the request was refused");
        anyhow::bail!("the authorization server refused the request ({code})");
    }

    let (Some(code), Some(state)) = (params.get("code"), params.get("state")) else {
        return Ok(None);
    };

    // Constant-time, and checked BEFORE the code is used for anything. A
    // mismatched state means this redirect belongs to some other flow — quite
    // possibly one an attacker started.
    if !crate::oauth::pkce::state_matches(expected_state, state) {
        anyhow::bail!(
            "the authorization response carried the wrong state parameter; the request was \
             discarded. Start the connection again."
        );
    }

    Ok(Some(CallbackResult {
        code: code.clone(),
        state: state.clone(),
    }))
}

async fn respond(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    message: &str,
) -> std::io::Result<()> {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Kunobi</title>\
         <body style=\"font:14px system-ui;padding:2rem\">{message}</body>"
    );
    let head = format!(
        "HTTP/1.1 {status} \r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An authorization code is single-use, but it IS a credential until it
    /// is redeemed — and this type travels through error paths.
    #[test]
    fn a_callback_result_never_prints_its_code() {
        let r = CallbackResult {
            code: "REVIEW_SECRET".into(),
            state: "st".into(),
        };
        let rendered = format!("{r:?}");
        assert!(!rendered.contains("REVIEW_SECRET"), "{rendered}");
        assert!(
            rendered.contains("st"),
            "the state is not a secret and stays legible"
        );
    }

    #[test]
    fn parses_a_successful_redirect() {
        let r = parse_callback_query("/callback?code=abc&state=st", "st")
            .unwrap()
            .unwrap();
        assert_eq!(r.code, "abc");
        assert_eq!(r.state, "st");
    }

    #[test]
    fn percent_encoded_values_are_decoded() {
        let r = parse_callback_query("/callback?code=a%2Fb%3Dc&state=st", "st")
            .unwrap()
            .unwrap();
        assert_eq!(r.code, "a/b=c");
    }

    /// A `state` mismatch must be an error, not a "keep waiting". Treating it
    /// as a stray connection hides a CSRF attempt behind a timeout.
    #[test]
    fn a_state_mismatch_is_an_error_not_a_skip() {
        let err = parse_callback_query("/callback?code=abc&state=wrong", "st")
            .unwrap_err()
            .to_string();
        assert!(err.contains("wrong state"), "{err}");
    }

    #[test]
    fn an_authorization_error_reports_its_code_but_never_its_description() {
        // `error_description` is free text the server chose. It routinely
        // echoes request parameters, and this message is logged and shown.
        let err = parse_callback_query(
            "/callback?state=st&error=access_denied&error_description=client_secret%3DREVIEW_SECRET",
            "st",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("access_denied"), "{err}");
        assert!(!err.contains("REVIEW_SECRET"), "{err}");
    }

    #[test]
    fn a_server_chosen_error_code_is_not_echoed_either() {
        let err = parse_callback_query(
            "/callback?state=st&error=client_secret%3DREVIEW_SECRET",
            "st",
        )
        .unwrap_err()
        .to_string();
        assert!(!err.contains("REVIEW_SECRET"), "{err}");
    }

    /// The CSRF guard applies to the ERROR path too.
    ///
    /// Without it, anyone who could reach this loopback port could end a flow
    /// they had no part in, with a message of their choosing.
    #[test]
    fn an_error_callback_with_the_wrong_state_is_refused_as_a_state_mismatch() {
        let err = parse_callback_query("/callback?state=someone-elses&error=access_denied", "st")
            .unwrap_err()
            .to_string();
        assert!(err.contains("wrong state"), "{err}");
    }

    #[test]
    fn an_error_callback_with_no_state_is_not_attributed_to_this_flow() {
        let out = parse_callback_query("/callback?error=access_denied", "st").unwrap();
        assert!(out.is_none(), "it cannot be attributed, so it is ignored");
    }

    #[test]
    fn unrelated_requests_are_skipped_rather_than_failing_the_flow() {
        assert!(
            parse_callback_query("/favicon.ico", "st")
                .unwrap()
                .is_none()
        );
        assert!(parse_callback_query("/callback", "st").unwrap().is_none());
        assert!(
            parse_callback_query("/callback?code=a", "st")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn only_get_is_accepted_as_a_redirect() {
        assert_eq!(
            request_target("GET /callback?code=a HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some("/callback?code=a")
        );
        assert!(request_target("POST /callback HTTP/1.1\r\n\r\n").is_none());
        assert!(request_target("").is_none());
    }

    #[tokio::test]
    async fn a_negotiable_listener_falls_back_when_the_port_is_taken() {
        let squatter = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let busy = squatter.local_addr().unwrap().port();

        let l = CallbackListener::bind(busy, PortPolicy::Negotiable, "/callback")
            .await
            .unwrap();
        assert_ne!(l.port(), busy);
        assert!(l.redirect_uri().starts_with("http://127.0.0.1:"));
        assert!(l.redirect_uri().ends_with("/callback"));
    }

    /// The finding from the live probe: for a pre-registered client the port is
    /// part of a promise already made to the authorization server, so a silent
    /// fallback produces `invalid_redirect_uri` after consent instead of a
    /// clear error before it.
    #[tokio::test]
    async fn a_fixed_listener_refuses_to_move_and_says_why() {
        let squatter = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let busy = squatter.local_addr().unwrap().port();

        let err = CallbackListener::bind(busy, PortPolicy::Fixed, "/callback")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(&busy.to_string()), "{err}");
        assert!(err.contains("pre-registered"), "{err}");
    }

    #[tokio::test]
    async fn the_redirect_uri_reflects_the_port_actually_bound() {
        let l = CallbackListener::bind(0, PortPolicy::Negotiable, "/callback")
            .await
            .unwrap();
        assert_eq!(
            l.redirect_uri(),
            format!("http://127.0.0.1:{}/callback", l.port())
        );
    }

    #[tokio::test]
    async fn wait_for_code_reads_the_redirect_and_ignores_a_stray_connection() {
        let l = CallbackListener::bind(0, PortPolicy::Negotiable, "/callback")
            .await
            .unwrap();
        let port = l.port();
        tokio::spawn(async move {
            // A probe that is not the redirect, then the real one.
            for target in [
                "GET /favicon.ico HTTP/1.1\r\n\r\n",
                "GET /callback?code=C&state=S HTTP/1.1\r\n\r\n",
            ] {
                let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap();
                s.write_all(target.as_bytes()).await.unwrap();
                let mut sink = Vec::new();
                let _ = s.read_to_end(&mut sink).await;
            }
        });
        let got = l.wait_for_code("S", Duration::from_secs(10)).await.unwrap();
        assert_eq!(got.code, "C");
    }

    /// The listener half of "an abandoned flow must not block a retry": when
    /// the browser never comes back, the timeout has to give the port up. It
    /// does so by consuming `self` — but that is only useful if the socket is
    /// actually closed, so the port is re-bound here to prove it.
    #[tokio::test]
    async fn the_consent_timeout_frees_the_port_for_a_retry() {
        let l = CallbackListener::bind(0, PortPolicy::Negotiable, "/callback")
            .await
            .unwrap();
        let port = l.port();
        assert!(
            l.wait_for_code("S", Duration::from_millis(50))
                .await
                .is_err()
        );

        let retry = CallbackListener::bind(port, PortPolicy::Fixed, "/callback")
            .await
            .expect("the abandoned flow's port must be re-bindable after its timeout");
        assert_eq!(retry.port(), port);
    }

    #[tokio::test]
    async fn wait_for_code_times_out_with_a_message_naming_the_redirect_uri() {
        let l = CallbackListener::bind(0, PortPolicy::Negotiable, "/callback")
            .await
            .unwrap();
        let uri = l.redirect_uri().to_string();
        let err = l
            .wait_for_code("S", Duration::from_millis(50))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(&uri), "{err}");
    }
}

//! The pure half of an authorization-code grant: build a request, parse a
//! response. No network, no browser, no clock.
//!
//! # Why this exists beside [`crate::oauth::flow`]
//!
//! `flow` runs the grant — it discovers, posts, and returns tokens, through the
//! [`crate::oauth::http_seam`]. That is what a host wants when it owns the whole flow.
//!
//! This layer is for a caller that owns the I/O itself: a CLI where the human
//! pastes the redirect URL back in, a transport that already has its own
//! configured HTTP client, or a test that wants the exact bytes without a
//! server. It arrived with the OpenAPI-to-MCP generator, which needed exactly
//! that shape, and it is kept because the property is genuinely useful — every
//! rule here is verifiable with no fixture at all.
//!
//! [`parse_callback`] in particular has no equivalent in `flow`: the loopback
//! listener in [`crate::oauth::callback`] parses the redirect it received itself,
//! whereas this takes a URL from anywhere and still refuses to skip the `state`
//! check.
//!
//! PKCE (RFC 7636) is what lets a public client authenticate without a secret,
//! which is what a desktop app has to be — anything shipped or stored locally
//! is readable by whoever runs it. [`crate::oauth::pkce::Pkce`] is the one
//! implementation; this module does not carry a second.

pub use crate::oauth::pkce::Pkce;

/// Everything needed to build one authorization request.
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    pub authorize_url: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    /// Random, single-use, and the only thing tying a callback back to the
    /// account whose flow started it.
    pub state: String,
    pub challenge: String,
}

impl AuthorizeRequest {
    /// The URL to open for the account holder to sign in and consent.
    pub fn url(&self) -> String {
        let separator = if self.authorize_url.contains('?') {
            '&'
        } else {
            '?'
        };
        format!(
            "{}{separator}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            self.authorize_url,
            percent_encode(&self.client_id),
            percent_encode(&self.redirect_uri),
            percent_encode(&self.scopes.join(" ")),
            percent_encode(&self.state),
            percent_encode(&self.challenge),
        )
    }
}

/// What came back on the redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    pub code: String,
    pub state: String,
}

// Hand-written, for the same reason `TokenSet`'s is: this struct IS the
// credential, and it travels through error paths where a stray `{:?}` prints it.
impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

/// Why a callback URL could not be turned into a [`Callback`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackError {
    /// The provider reported a failure instead of issuing a code.
    Denied {
        error: String,
        description: Option<String>,
    },
    /// `state` did not match the flow in progress. Treated as hostile, not as a
    /// mistake: it is the CSRF guard, and on a shared redirect URI it is also
    /// what keeps one account's callback from completing another's flow.
    StateMismatch { expected: String, received: String },
    /// No `code` and no `error` — not a callback from this flow.
    Malformed,
}

/// Parse a redirect URL, checking `state` against the flow that started it.
///
/// Takes the whole URL rather than pre-split parameters so the caller cannot
/// forget the `state` check; it is not optional.
pub fn parse_callback(url: &str, expected_state: &str) -> Result<Callback, CallbackError> {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut description = None;

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value);
        match key {
            "code" => code = Some(value),
            "state" => state = Some(value),
            "error" => error = Some(value),
            "error_description" => description = Some(value),
            _ => {}
        }
    }

    // State is checked BEFORE a denial is reported.
    //
    // This used to report the provider's error first, on the reasoning that a
    // denial is more useful than a mismatch. It is not, when the denial cannot
    // be attributed: on a shared redirect URI that let a callback belonging to
    // some other flow — or to nobody — end this one, with a message of the
    // sender's choosing. The CSRF guard is not only for the success path.
    if let Some(state) = state.as_deref() {
        if state != expected_state {
            return Err(CallbackError::StateMismatch {
                expected: expected_state.to_string(),
                received: state.to_string(),
            });
        }
    } else if error.is_some() {
        // An error with no state cannot be attributed to this flow at all.
        return Err(CallbackError::Malformed);
    }

    if let Some(error) = error {
        return Err(CallbackError::Denied { error, description });
    }

    let (Some(code), Some(state)) = (code, state) else {
        return Err(CallbackError::Malformed);
    };

    Ok(Callback { code, state })
}

/// The form body for exchanging an authorization code for tokens.
///
/// Returned as pairs rather than an encoded string so a caller can hand them to
/// whatever HTTP client it already has. `client_secret` is absent by
/// construction: this is a public client, and PKCE's verifier is what proves
/// the exchange belongs to the flow that started it.
pub fn exchange_form(
    code: &str,
    verifier: &str,
    client_id: &str,
    redirect_uri: &str,
) -> Vec<(String, String)> {
    pairs(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("code_verifier", verifier),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
    ])
}

/// The form body for exchanging a refresh token for a new pair.
pub fn refresh_form(refresh_token: &str, client_id: &str) -> Vec<(String, String)> {
    pairs(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ])
}

fn pairs(fields: &[(&str, &str)]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// A token pair as the provider issued it.
#[derive(Clone, PartialEq, Eq)]
pub struct Tokens {
    pub access_token: String,
    /// X rotates this on every use, so the value here supersedes whatever was
    /// stored — and must be persisted before the old one is discarded.
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    /// Scopes actually granted, which can be narrower than those requested when
    /// the account holder declines individually.
    pub scopes: Vec<String>,
}

/// Why a token response could not be turned into [`Tokens`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// The provider returned an OAuth error object.
    Provider {
        error: String,
        description: Option<String>,
    },
    /// Valid JSON, but not a token response.
    Malformed(String),
}

/// Parse a token endpoint response body.
pub fn parse_token_response(body: &str) -> Result<Tokens, TokenError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| TokenError::Malformed(format!("not JSON: {e}")))?;

    if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
        return Err(TokenError::Provider {
            error: error.to_string(),
            description: value
                .get("error_description")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        });
    }

    let access_token = value
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TokenError::Malformed("no access_token".to_string()))?
        .to_string();

    Ok(Tokens {
        access_token,
        refresh_token: value
            .get("refresh_token")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        expires_in: value.get("expires_in").and_then(serde_json::Value::as_u64),
        scopes: value
            .get("scope")
            .and_then(serde_json::Value::as_str)
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default(),
    })
}

/// Percent-encode everything outside the unreserved set of RFC 3986.
///
/// Hand-rolled rather than pulled from a URL crate: the encoding rules are
/// eight lines and fully covered by tests, against a dependency this pure crate
/// would otherwise not need.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Decode percent-escapes and `+`-as-space. Invalid escapes are left verbatim,
/// so a malformed value is visible rather than silently mangled.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&value[i + 1..i + 3], 16) {
                Ok(decoded) => {
                    out.push(decoded);
                    i += 3;
                }
                Err(_) => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AuthorizeRequest {
        AuthorizeRequest {
            authorize_url: "https://x.com/i/oauth2/authorize".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "kunobi://x/callback".to_string(),
            scopes: vec!["tweet.read".to_string(), "offline.access".to_string()],
            state: "st4te".to_string(),
            challenge: "ch4llenge".to_string(),
        }
    }

    // The PKCE tests that used to live here moved with the implementation to
    // `crate::oauth::pkce` — this module re-exports that type rather than carrying a
    // second one.

    #[test]
    fn authorize_url_carries_every_required_parameter() {
        let url = request().url();
        for expected in [
            "response_type=code",
            "client_id=test-client",
            "state=st4te",
            "code_challenge=ch4llenge",
            "code_challenge_method=S256",
        ] {
            assert!(url.contains(expected), "missing {expected} in {url}");
        }
    }

    #[test]
    fn authorize_url_percent_encodes_the_redirect_uri() {
        // `kunobi://x/callback` has characters that would otherwise terminate
        // the query string.
        let url = request().url();
        assert!(
            url.contains("redirect_uri=kunobi%3A%2F%2Fx%2Fcallback"),
            "{url}"
        );
    }

    #[test]
    fn authorize_url_joins_scopes_with_spaces() {
        let url = request().url();
        assert!(url.contains("scope=tweet.read%20offline.access"), "{url}");
    }

    #[test]
    fn parses_a_successful_callback() {
        let parsed = parse_callback("kunobi://x/callback?code=abc123&state=st4te", "st4te");
        assert_eq!(
            parsed,
            Ok(Callback {
                code: "abc123".to_string(),
                state: "st4te".to_string(),
            })
        );
    }

    #[test]
    fn a_state_mismatch_is_rejected() {
        let parsed = parse_callback("kunobi://x/callback?code=abc&state=wrong", "st4te");
        assert_eq!(
            parsed,
            Err(CallbackError::StateMismatch {
                expected: "st4te".to_string(),
                received: "wrong".to_string(),
            })
        );
    }

    #[test]
    fn a_valid_code_with_the_wrong_state_is_still_rejected() {
        // The case that matters: on one shared redirect URI, account B's
        // callback must not be able to complete account A's flow.
        assert!(parse_callback("kunobi://x/callback?code=real&state=b", "a").is_err());
    }

    #[test]
    fn a_denial_carrying_this_flows_state_reports_the_provider_error() {
        let parsed = parse_callback(
            "kunobi://x/callback?state=st4te&error=access_denied&error_description=user%20said%20no",
            "st4te",
        );
        assert_eq!(
            parsed,
            Err(CallbackError::Denied {
                error: "access_denied".to_string(),
                description: Some("user said no".to_string()),
            })
        );
    }

    /// The CSRF guard applies to the error path too.
    ///
    /// Reporting a denial before checking state let a callback belonging to
    /// another flow — or to nobody — end this one, with a message of the
    /// sender's choosing.
    #[test]
    fn a_denial_carrying_someone_elses_state_is_a_mismatch_not_a_denial() {
        let parsed = parse_callback(
            "kunobi://x/callback?state=someone-else&error=access_denied",
            "st4te",
        );
        assert!(
            matches!(parsed, Err(CallbackError::StateMismatch { .. })),
            "{parsed:?}"
        );
    }

    #[test]
    fn a_denial_with_no_state_cannot_be_attributed_to_this_flow() {
        let parsed = parse_callback("kunobi://x/callback?error=access_denied", "st4te");
        assert_eq!(parsed, Err(CallbackError::Malformed));
    }

    #[test]
    fn tokens_never_print_themselves() {
        let t = Tokens {
            access_token: "REVIEW_SECRET".into(),
            refresh_token: Some("REVIEW_SECRET".into()),
            expires_in: Some(3600),
            scopes: vec!["read".into()],
        };
        let rendered = format!("{t:?}");
        assert!(!rendered.contains("REVIEW_SECRET"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn a_url_with_neither_code_nor_error_is_malformed() {
        assert_eq!(
            parse_callback("kunobi://x/callback", "st4te"),
            Err(CallbackError::Malformed)
        );
    }

    fn field<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn exchange_form_carries_the_code_and_verifier() {
        let form = exchange_form("the-code", "the-verifier", "cid", "kunobi://x/callback");
        assert_eq!(field(&form, "grant_type"), Some("authorization_code"));
        assert_eq!(field(&form, "code"), Some("the-code"));
        assert_eq!(field(&form, "code_verifier"), Some("the-verifier"));
        assert_eq!(field(&form, "client_id"), Some("cid"));
        assert_eq!(field(&form, "redirect_uri"), Some("kunobi://x/callback"));
    }

    #[test]
    fn exchange_form_sends_no_client_secret() {
        // A public client has none, and sending an empty one is rejected as a
        // malformed request rather than ignored.
        let form = exchange_form("c", "v", "cid", "r");
        assert_eq!(field(&form, "client_secret"), None, "{form:?}");
    }

    #[test]
    fn refresh_form_uses_the_refresh_grant() {
        let form = refresh_form("r3fresh", "cid");
        assert_eq!(field(&form, "grant_type"), Some("refresh_token"));
        assert_eq!(field(&form, "refresh_token"), Some("r3fresh"));
        assert_eq!(field(&form, "client_id"), Some("cid"));
        assert_eq!(field(&form, "client_secret"), None);
    }

    #[test]
    fn parses_a_token_response() {
        let parsed = parse_token_response(
            r#"{"token_type":"bearer","expires_in":7200,
                "access_token":"at","refresh_token":"rt",
                "scope":"tweet.read tweet.write offline.access"}"#,
        );
        assert_eq!(
            parsed,
            Ok(Tokens {
                access_token: "at".to_string(),
                refresh_token: Some("rt".to_string()),
                expires_in: Some(7200),
                scopes: vec![
                    "tweet.read".to_string(),
                    "tweet.write".to_string(),
                    "offline.access".to_string()
                ],
            })
        );
    }

    #[test]
    fn a_response_without_a_refresh_token_is_still_valid() {
        // What you get when offline.access was not granted. The account works
        // until the access token expires and then needs re-authorizing, so this
        // has to parse rather than fail — the caller decides what it means.
        let parsed = parse_token_response(r#"{"access_token":"at","expires_in":7200}"#).unwrap();
        assert_eq!(parsed.refresh_token, None);
        assert!(parsed.scopes.is_empty());
    }

    #[test]
    fn a_provider_error_is_reported_with_its_description() {
        let parsed =
            parse_token_response(r#"{"error":"invalid_grant","error_description":"code expired"}"#);
        assert_eq!(
            parsed,
            Err(TokenError::Provider {
                error: "invalid_grant".to_string(),
                description: Some("code expired".to_string()),
            })
        );
    }

    #[test]
    fn a_response_without_an_access_token_is_malformed() {
        assert!(matches!(
            parse_token_response(r#"{"token_type":"bearer"}"#),
            Err(TokenError::Malformed(_))
        ));
    }

    #[test]
    fn a_non_json_response_is_malformed_rather_than_a_panic() {
        // Providers return HTML error pages more often than anyone expects.
        assert!(matches!(
            parse_token_response("<html>502 Bad Gateway</html>"),
            Err(TokenError::Malformed(_))
        ));
    }

    #[test]
    fn a_percent_encoded_code_is_decoded() {
        let parsed = parse_callback("kunobi://x/callback?code=a%2Bb%2Fc&state=st4te", "st4te");
        assert_eq!(parsed.unwrap().code, "a+b/c");
    }
}

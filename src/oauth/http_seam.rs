//! The one place OAuth touches the network.
//!
//! Discovery, registration and token exchange are all "fetch a JSON document,
//! interpret it". Putting that behind a trait keeps every rule in
//! [`crate::oauth::flow`] — candidate ordering, 404-means-try-the-next-one, refusing a
//! non-`none` token endpoint — unit-testable without a live server, which is
//! the only way the ordering findings in [`crate::oauth::discovery`] stay verified.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use url::Url;

/// A JSON response: the status plus the parsed body, if it parsed.
#[derive(Clone)]
pub struct JsonResponse {
    /// The HTTP status code of the response.
    pub status: u16,
    /// The parsed JSON body, when the response parsed as JSON.
    pub body: Option<serde_json::Value>,
    /// Raw body, retained for diagnosis when `body` did not parse.
    ///
    /// Never reaches a message: [`JsonResponse::error_summary`] reports the
    /// status and an allowlisted error code, and nothing else.
    pub raw: String,
    /// The `WWW-Authenticate` header, verbatim, when the response carried one.
    ///
    /// Only meaningful on the unauthenticated probe: RFC 9728 §5.1 makes this
    /// header the authoritative pointer to a resource's metadata, and it is the
    /// only way to find metadata that does not live on the MCP server's own
    /// host. Carried on [`JsonResponse`] rather than a header map because it is
    /// the single header any part of this flow acts on.
    pub www_authenticate: Option<String>,
}

/// The error codes RFC 6749 §5.2 and RFC 8414 define.
///
/// An allowlist rather than a filter: a code outside this set is a value the
/// server chose, and passing it through is how arbitrary response text reaches
/// a log line.
const RFC6749_ERROR_CODES: &[&str] = &[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "access_denied",
    "unsupported_response_type",
    "server_error",
    "temporarily_unavailable",
    "invalid_token",
    "insufficient_scope",
    // RFC 7591 §3.2.2, for the dynamic-registration endpoint.
    "invalid_redirect_uri",
    "invalid_client_metadata",
    "invalid_software_statement",
    "unapproved_software_statement",
];

// Hand-written: a token endpoint's response body IS the credential, and both
// `body` and `raw` hold it verbatim. Deriving `Debug` here put an access token
// one stray `{:?}` away from a log line.
impl std::fmt::Debug for JsonResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonResponse")
            .field("status", &self.status)
            .field("body", &self.body.as_ref().map(|_| "<redacted>"))
            .field("raw_len", &self.raw.len())
            .field("www_authenticate", &self.www_authenticate)
            .finish()
    }
}

impl JsonResponse {
    /// Whether the status is in the 2xx range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// A short, bounded description for an error message.
    ///
    /// # Why this does not include the response text
    ///
    /// It used to fall back to the first 200 raw characters, and truncation is
    /// not redaction. A token endpoint's `error_description` routinely echoes
    /// request parameters, and this string travels into logs, into user-visible
    /// errors, and — for the gateway — into a persisted status reason. A server
    /// that echoed the request would put the client secret in all three.
    ///
    /// So only the RFC 6749 §5.2 error CODE is passed through, and only when it
    /// is one of the codes that RFC defines. Anything else becomes the status
    /// alone, which is enough to tell the user what to do and cannot carry a
    /// credential.
    pub fn error_summary(&self) -> String {
        let code = self
            .body
            .as_ref()
            .and_then(|b| b.get("error").and_then(|e| e.as_str()))
            .filter(|c| RFC6749_ERROR_CODES.contains(c));

        match code {
            Some(code) => format!("HTTP {}: {code}", self.status),
            None => format!("HTTP {}", self.status),
        }
    }
}

/// The network seam. Implemented by [`ReqwestHttp`] in production and by a
/// scripted fake in tests.
#[async_trait]
pub trait OAuthHttp: Send + Sync {
    /// Fetches a JSON document from the given URL.
    async fn get_json(&self, url: &Url) -> anyhow::Result<JsonResponse>;
    /// One unauthenticated request to an MCP endpoint, made only to read the
    /// `WWW-Authenticate` challenge it answers with.
    ///
    /// Separate from [`OAuthHttp::post_json`] because the request shape is
    /// MCP-specific (a JSON-RPC `initialize` with the streamable-HTTP `accept`
    /// header) and because the interesting part of the answer is a header, not
    /// a body. Best-effort by contract: the caller treats any failure as "no
    /// challenge" and falls back to probing.
    async fn probe_challenge(&self, url: &Url) -> anyhow::Result<JsonResponse>;
    /// Posts form fields to the given URL with optional Basic auth.
    async fn post_form(
        &self,
        url: &Url,
        form: &[(String, String)],
        basic_auth: Option<(String, String)>,
    ) -> anyhow::Result<JsonResponse>;
    /// Posts a JSON body to the given URL.
    async fn post_json(&self, url: &Url, body: &serde_json::Value) -> anyhow::Result<JsonResponse>;
}

/// How long the unauthenticated challenge probe may take.
///
/// Much shorter than the general timeout: the probe is an optimisation, and a
/// server that is slow to say "401" must not add twenty seconds to every
/// connect before the well-known fallback even starts.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Production implementation.
///
/// A short timeout on every call: an authorization server that hangs must not
/// wedge the tool call that started the flow.
pub struct ReqwestHttp {
    /// For the GET fetches (metadata discovery) and the unauthenticated MCP
    /// challenge probe, where a redirect is a normal part of how documents are
    /// published. Bounded by [`redirect_allowed`] and a five-hop cap.
    client: reqwest::Client,
    /// For the POSTs that carry a secret: token exchange, token refresh, and
    /// dynamic client registration. Follows nothing at all.
    ///
    /// Two clients rather than one, because `reqwest` sets its redirect policy
    /// per client and these two request families want opposite answers. Neither
    /// RFC 6749 (token endpoint) nor RFC 7591 (registration endpoint) gives a
    /// redirect from those endpoints any meaning, so there is nothing to lose
    /// by refusing: a 3xx surfaces as a non-2xx and the caller reports a failed
    /// exchange. What it buys is that no same-origin 307 can replay the
    /// authorization code and PKCE verifier onto a second path the
    /// authorization server never meant to hold them — a hole that tightening
    /// [`redirect_allowed`] alone leaves open, since same-origin redirects are
    /// exactly the ones that rule permits.
    no_redirect: reqwest::Client,
}

/// Whether a redirect from `from` to `to` may be followed.
///
/// `reqwest`'s default policy follows up to ten redirects anywhere, including
/// to another host or down to plaintext. That was tolerable while every URL
/// this client fetched was derived from an already-validated https MCP URL. It
/// is not tolerable now that a resource-metadata URL can arrive from a
/// `WWW-Authenticate` challenge or from a tool argument: a 302 is a second,
/// unvalidated chance to move the fetch somewhere else, and `require_https`
/// and the RFC 9728 §3.3 resource check only see the URL we *asked* for.
///
/// So: the **same origin** — scheme, host and effective port, as RFC 6454 §4
/// defines it — and never a downgrade off https (loopback http excepted, to
/// match [`crate::oauth::flow`]'s rule for local testing). Extracted as a pure
/// function so the rule is unit-testable without a live redirecting server;
/// `policy_tests` covers whether it is actually installed on the client.
///
/// The port is part of the comparison and not an afterthought: "same host" put
/// `https://auth.example/token` and `https://auth.example:8443/token` in one
/// bucket, and they are two different services. A 307/308 between them
/// preserves the request body (RFC 7231 §6.4.7), which on the token endpoint is
/// the authorization code and the PKCE verifier.
pub(crate) fn redirect_allowed(from: &Url, to: &Url) -> bool {
    let to_is_loopback = matches!(to.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if to.scheme() != "https" && !(to.scheme() == "http" && to_is_loopback) {
        return false;
    }
    from.scheme() == to.scheme()
        && from.host_str() == to.host_str()
        && from.port_or_known_default() == to.port_or_known_default()
}

impl ReqwestHttp {
    /// Creates an HTTP client with the production timeouts and redirect policy.
    pub fn new() -> anyhow::Result<Self> {
        let base = || {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .user_agent("kunobi-agentgateway")
        };
        Ok(Self {
            no_redirect: base().redirect(reqwest::redirect::Policy::none()).build()?,
            client: base()
                .redirect(reqwest::redirect::Policy::custom(|attempt| {
                    // Five hops is already generous for a metadata document.
                    if attempt.previous().len() >= 5 {
                        return attempt.stop();
                    }
                    match attempt.previous().last() {
                        Some(from) if redirect_allowed(from, attempt.url()) => attempt.follow(),
                        // `stop` rather than `error`: the caller sees the 3xx as
                        // a non-success response and moves to the next
                        // candidate, which is the same shape as a 404.
                        _ => attempt.stop(),
                    }
                }))
                .build()?,
        })
    }
}

impl ReqwestHttp {
    async fn finish(resp: reqwest::Response) -> anyhow::Result<JsonResponse> {
        let status = resp.status().as_u16();
        let www_authenticate = resp
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let raw = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str(&raw).ok();
        Ok(JsonResponse {
            status,
            body,
            raw,
            www_authenticate,
        })
    }
}

#[async_trait]
impl OAuthHttp for ReqwestHttp {
    async fn get_json(&self, url: &Url) -> anyhow::Result<JsonResponse> {
        let resp = self
            .client
            .get(url.as_str())
            .header("accept", "application/json")
            .send()
            .await?;
        Self::finish(resp).await
    }

    async fn probe_challenge(&self, url: &Url) -> anyhow::Result<JsonResponse> {
        // A JSON-RPC `initialize`: the first thing any MCP client sends, so a
        // server that gates on authorization answers it with the 401 challenge
        // we are here to read. Nothing is retried and nothing is stored.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "kunobi-agentgateway", "version": "0" }
            }
        });
        let resp = self
            .client
            .post(url.as_str())
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .timeout(PROBE_TIMEOUT)
            .json(&body)
            .send()
            .await?;
        Self::finish(resp).await
    }

    async fn post_form(
        &self,
        url: &Url,
        form: &[(String, String)],
        basic_auth: Option<(String, String)>,
    ) -> anyhow::Result<JsonResponse> {
        let mut req = self
            .no_redirect
            .post(url.as_str())
            .header("accept", "application/json")
            .form(form);
        if let Some((user, pass)) = basic_auth {
            req = req.basic_auth(user, Some(pass));
        }
        Self::finish(req.send().await?).await
    }

    async fn post_json(&self, url: &Url, body: &serde_json::Value) -> anyhow::Result<JsonResponse> {
        let resp = self
            .no_redirect
            .post(url.as_str())
            .header("accept", "application/json")
            .json(body)
            .send()
            .await?;
        Self::finish(resp).await
    }
}

/// A scripted `OAuthHttp` for tests: exact-URL lookup, everything else 404.
///
/// Test-only, but compiled into the crate rather than gated behind `#[cfg(test)]`
/// so the injector's integration tests (a separate test module) can share it.
/// One recorded form POST: the URL, and the pairs that were sent.
/// One recorded `post_form`: the URL, the form fields, and the HTTP Basic
/// credentials the caller supplied.
///
/// The Basic pair used to be dropped on the floor here. That made client
/// authentication invisible to every test — a flow could send a secret, send
/// the wrong one, or send none at all, and the fake looked identical. Since
/// `client_secret_basic` is the RFC 8414 default whenever a server omits
/// `token_endpoint_auth_methods_supported`, that is exactly the path most
/// likely to be wrong and least likely to be noticed.
pub type RecordedForm = (String, Vec<(String, String)>, Option<(String, String)>);

#[derive(Default)]
#[allow(clippy::type_complexity)]
/// A scripted OAuthHttp for tests keyed by exact URL.
pub struct FakeHttp {
    /// Scripted GET responses keyed by URL.
    pub gets: HashMap<String, JsonResponse>,
    /// Scripted POST responses keyed by URL.
    pub posts: HashMap<String, JsonResponse>,
    /// Scripted answers to [`OAuthHttp::probe_challenge`], keyed by MCP URL.
    pub challenges: HashMap<String, JsonResponse>,
    /// Recorded form POSTs made through the fake, in order.
    pub recorded_forms: std::sync::Mutex<Vec<RecordedForm>>,
    /// Recorded JSON POSTs made through the fake, in order.
    pub recorded_json: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
    /// Runs while a `post_form` is "in flight", after it has yielded.
    ///
    /// The point is scheduling, not scripting: a test that wants something to
    /// happen DURING a request — a disconnect landing mid-refresh — needs it to
    /// interleave at the real suspension point rather than be ordered by hand
    /// before or after the call.
    #[allow(clippy::type_complexity)]
    pub during_post: std::sync::Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl FakeHttp {
    /// The most recent `post_form` body, or `None` if nothing was posted.
    pub fn last_form(&self) -> Option<Vec<(String, String)>> {
        self.recorded_forms
            .lock()
            .unwrap()
            .last()
            .map(|(_, form, _)| form.clone())
    }

    /// The HTTP Basic credentials sent with the most recent `post_form`.
    ///
    /// `Some(None)` means a request was made with no Basic auth, which is a
    /// different assertion from `None` ("no request was made") and the two must
    /// not be collapsed.
    pub fn last_basic_auth(&self) -> Option<Option<(String, String)>> {
        self.recorded_forms
            .lock()
            .unwrap()
            .last()
            .map(|(_, _, basic)| basic.clone())
    }

    /// Builds a JSON response with the given status and body.
    pub fn json(status: u16, value: serde_json::Value) -> JsonResponse {
        JsonResponse {
            status,
            raw: value.to_string(),
            body: Some(value),
            www_authenticate: None,
        }
    }

    /// Builds a 404 response with no body.
    pub fn not_found() -> JsonResponse {
        JsonResponse {
            status: 404,
            body: None,
            raw: "not found".to_string(),
            www_authenticate: None,
        }
    }

    /// A 401 carrying a verbatim `WWW-Authenticate` header — the shape a
    /// gated MCP server answers an unauthenticated `initialize` with.
    pub fn with_challenge(mut self, mcp_url: &str, www_authenticate: &str) -> Self {
        self.challenges.insert(
            mcp_url.to_string(),
            JsonResponse {
                status: 401,
                body: None,
                raw: String::new(),
                www_authenticate: Some(www_authenticate.to_string()),
            },
        );
        self
    }

    /// Scripts a GET response for the given URL.
    pub fn with_get(mut self, url: &str, resp: JsonResponse) -> Self {
        self.gets.insert(url.to_string(), resp);
        self
    }

    /// Run `f` while a `post_form` is suspended. See [`FakeHttp::during_post`].
    pub fn on_post(self, f: impl Fn() + Send + Sync + 'static) -> Self {
        *self.during_post.lock().unwrap() = Some(Box::new(f));
        self
    }

    /// Scripts a POST response for the given URL.
    pub fn with_post(mut self, url: &str, resp: JsonResponse) -> Self {
        self.posts.insert(url.to_string(), resp);
        self
    }

    /// Every GET URL the code under test attempted, in order — the assertion
    /// surface for discovery ordering.
    pub fn form_for(&self, url: &str) -> Option<Vec<(String, String)>> {
        self.recorded_forms
            .lock()
            .unwrap()
            .iter()
            .find(|(u, _, _)| u == url)
            .map(|(_, f, _)| f.clone())
    }
}

#[async_trait]
impl OAuthHttp for FakeHttp {
    async fn get_json(&self, url: &Url) -> anyhow::Result<JsonResponse> {
        Ok(self
            .gets
            .get(url.as_str())
            .cloned()
            .unwrap_or_else(Self::not_found))
    }

    async fn probe_challenge(&self, url: &Url) -> anyhow::Result<JsonResponse> {
        Ok(self
            .challenges
            .get(url.as_str())
            .cloned()
            .unwrap_or_else(Self::not_found))
    }

    async fn post_form(
        &self,
        url: &Url,
        form: &[(String, String)],
        basic_auth: Option<(String, String)>,
    ) -> anyhow::Result<JsonResponse> {
        // A real token request suspends; this fake must too, or it is not a
        // stand-in for one.
        //
        // Without a suspension point every `async fn` here runs straight
        // through, so on the default current-thread test runtime N spawned
        // tasks execute strictly one after another and never contend. Any test
        // that spawns concurrent callers to prove a lock does something then
        // passes whether or not the lock exists — which is exactly what
        // `concurrent_refreshes_are_single_flight` did before this line: with
        // `refresh_lock` deleted it still reported ok.
        //
        // `yield_now` restores the interleaving the fake is supposed to
        // represent, so a missing lock shows up as N recorded requests instead
        // of one.
        tokio::task::yield_now().await;
        if let Some(f) = self.during_post.lock().unwrap().as_ref() {
            f();
        }
        self.recorded_forms
            .lock()
            .unwrap()
            .push((url.to_string(), form.to_vec(), basic_auth));
        Ok(self
            .posts
            .get(url.as_str())
            .cloned()
            .unwrap_or_else(Self::not_found))
    }

    async fn post_json(&self, url: &Url, body: &serde_json::Value) -> anyhow::Result<JsonResponse> {
        self.recorded_json
            .lock()
            .unwrap()
            .push((url.to_string(), body.clone()));
        Ok(self
            .posts
            .get(url.as_str())
            .cloned()
            .unwrap_or_else(Self::not_found))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_summary_prefers_the_oauth_error_code() {
        let r = FakeHttp::json(400, serde_json::json!({"error": "invalid_grant"}));
        assert_eq!(r.error_summary(), "HTTP 400: invalid_grant");
    }

    /// A token endpoint's response body IS the credential. Deriving `Debug`
    /// here put an access token one stray `{:?}` away from a log line.
    #[test]
    fn a_json_response_never_prints_its_body() {
        let r = JsonResponse {
            status: 200,
            body: Some(serde_json::json!({"access_token": "REVIEW_SECRET"})),
            raw: "access_token=REVIEW_SECRET".into(),
            www_authenticate: None,
        };
        let rendered = format!("{r:?}");
        assert!(!rendered.contains("REVIEW_SECRET"), "{rendered}");
        assert!(rendered.contains("status: 200"), "the useful part survives");
    }

    #[test]
    fn error_summary_never_includes_response_text() {
        // This used to TRUNCATE the raw body to 200 characters, and truncation
        // is not redaction: the summary travels into logs, into user-visible
        // errors, and into a persisted status reason.
        let r = JsonResponse {
            status: 500,
            body: None,
            raw: "client_secret=REVIEW_SECRET and more".repeat(20),
            www_authenticate: None,
        };
        let s = r.error_summary();
        assert!(!s.contains("REVIEW_SECRET"), "{s}");
        assert_eq!(s, "HTTP 500");
    }

    #[test]
    fn error_summary_passes_through_only_a_known_error_code() {
        let known = JsonResponse {
            status: 400,
            body: Some(serde_json::json!({"error": "invalid_grant"})),
            raw: String::new(),
            www_authenticate: None,
        };
        assert_eq!(known.error_summary(), "HTTP 400: invalid_grant");
    }

    #[test]
    fn a_server_chosen_error_code_is_not_passed_through() {
        // The `error` field is server-controlled text. An allowlist is what
        // stops it becoming an arbitrary-string channel into a log line.
        let hostile = JsonResponse {
            status: 400,
            body: Some(serde_json::json!({"error": "client_secret=REVIEW_SECRET"})),
            raw: String::new(),
            www_authenticate: None,
        };
        let s = hostile.error_summary();
        assert!(!s.contains("REVIEW_SECRET"), "{s}");
        assert_eq!(s, "HTTP 400");
    }

    #[test]
    fn an_error_description_is_never_included() {
        // RFC 6749 §5.2 allows `error_description` to be free text, and token
        // endpoints routinely echo request parameters into it.
        let echoing = JsonResponse {
            status: 400,
            body: Some(serde_json::json!({
                "error": "invalid_request",
                "error_description": "bad client_secret=REVIEW_SECRET",
            })),
            raw: String::new(),
            www_authenticate: None,
        };
        let s = echoing.error_summary();
        assert!(!s.contains("REVIEW_SECRET"), "{s}");
        assert_eq!(s, "HTTP 400: invalid_request");
    }

    /// The redirect rule, stated as cases. A metadata fetch that can be
    /// bounced to another host is a second, unvalidated hop that neither
    /// `require_https` nor the RFC 9728 §3.3 resource check would see.
    ///
    /// This covers the rule only. Whether the rule is *installed* on the
    /// shipped client is a separate question, and one this test cannot answer:
    /// see `policy_tests` below, which drives the real client against loopback
    /// servers and counts the requests it makes.
    #[test]
    fn redirects_may_not_change_host_or_drop_to_plaintext() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(redirect_allowed(
            &u("https://a.example/.well-known/x"),
            &u("https://a.example/metadata")
        ));
        assert!(
            !redirect_allowed(&u("https://a.example/x"), &u("https://evil.example/x")),
            "a cross-host redirect must not be followed"
        );
        assert!(
            !redirect_allowed(&u("https://a.example/x"), &u("http://a.example/x")),
            "a downgrade to plaintext must not be followed"
        );
        // Loopback http stays reachable, matching the flow's own https rule.
        assert!(redirect_allowed(
            &u("http://127.0.0.1:8080/a"),
            &u("http://127.0.0.1:8080/b")
        ));
        assert!(
            !redirect_allowed(
                &u("https://auth.example/token"),
                &u("https://auth.example:8443/token")
            ),
            "a different port is a different service, even on the same host"
        );
        assert!(
            redirect_allowed(
                &u("https://auth.example/a"),
                &u("https://auth.example:443/b")
            ),
            "the default port stated explicitly is the same origin"
        );
        assert!(
            !redirect_allowed(&u("http://127.0.0.1:1/a"), &u("http://127.0.0.1:2/b")),
            "loopback is not one origin: two ports are two processes"
        );
    }

    #[test]
    fn success_range_is_2xx_only() {
        assert!(FakeHttp::json(200, serde_json::json!({})).is_success());
        assert!(FakeHttp::json(299, serde_json::json!({})).is_success());
        assert!(!FakeHttp::json(300, serde_json::json!({})).is_success());
        assert!(!FakeHttp::json(401, serde_json::json!({})).is_success());
    }
}

/// Tests that exercise the **real** [`ReqwestHttp`] client against loopback
/// servers, rather than the pure [`redirect_allowed`] helper.
///
/// The helper on its own is vacuous as a guard: deleting
/// `.redirect(Policy::custom(..))` from [`ReqwestHttp::new`], or the hop cap
/// inside it, leaves every assertion about it green while the shipped client
/// happily follows a redirect anywhere. These tests fail in exactly those two
/// cases, because they observe what the client does on the wire.
#[cfg(test)]
mod policy_tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A loopback HTTP server that records every request it receives and
    /// answers with whatever `respond` returns for that request's index.
    ///
    /// Hand-rolled rather than pulled in as a dependency: the whole point is to
    /// observe how many requests the client actually makes, which needs nothing
    /// more than a `TcpListener` and one `write_all`.
    struct TestServer {
        port: u16,
        requests: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl TestServer {
        fn hits(&self) -> usize {
            self.requests.lock().unwrap().len()
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve<F>(respond: F) -> TestServer
    where
        F: Fn(usize) -> String + Send + Sync + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 8192];
                let Ok(n) = stream.read(&mut buf).await else {
                    continue;
                };
                let index = {
                    let mut s = seen.lock().unwrap();
                    s.push(String::from_utf8_lossy(&buf[..n]).to_string());
                    s.len() - 1
                };
                let _ = stream.write_all(respond(index).as_bytes()).await;
                let _ = stream.flush().await;
            }
        });
        TestServer {
            port,
            requests,
            task,
        }
    }

    fn redirect(status: u16, location: &str) -> String {
        format!(
            "HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        )
    }

    fn ok_json(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// Deleting `.redirect(Policy::custom(..))` makes this fail: `reqwest`'s
    /// default policy follows up to ten hops anywhere, so the destination would
    /// be reached and its body returned.
    ///
    /// `localhost` and `127.0.0.1` are different hosts by the rule's own
    /// comparison while both resolving to this one loopback server, which is
    /// what lets a single process observe whether the cross-host hop was taken.
    #[tokio::test]
    async fn the_client_does_not_follow_a_cross_host_redirect() {
        // The redirect target names the port, which only exists once the
        // listener is bound, so it is filled in after `serve` returns.
        let hop = Arc::new(Mutex::new(String::new()));
        let target = hop.clone();
        let server = serve(move |index| {
            if index == 0 {
                redirect(302, &target.lock().unwrap().clone())
            } else {
                ok_json(r#"{"marker":"followed"}"#)
            }
        })
        .await;
        *hop.lock().unwrap() = format!("http://localhost:{}/elsewhere", server.port);

        let http = ReqwestHttp::new().unwrap();
        let resp = http
            .get_json(&Url::parse(&format!("http://127.0.0.1:{}/start", server.port)).unwrap())
            .await
            .unwrap();

        assert_eq!(
            resp.status, 302,
            "the 3xx must be surfaced to the caller, not followed"
        );
        assert_eq!(
            server.hits(),
            1,
            "the client must not have made the second, cross-host request"
        );
    }

    /// Deleting the five-hop cap makes this fail: `reqwest`'s default limit of
    /// ten would take over, and an eleventh hop is an error rather than a
    /// surfaced 3xx, so `get_json` would return `Err`.
    #[tokio::test]
    async fn the_client_stops_following_same_origin_redirects_at_the_hop_cap() {
        let server = serve(|index| redirect(302, &format!("/hop{}", index + 1))).await;

        let http = ReqwestHttp::new().unwrap();
        let resp = http
            .get_json(&Url::parse(&format!("http://127.0.0.1:{}/hop0", server.port)).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status, 302);
        assert_eq!(
            server.hits(),
            5,
            "the original request plus four follows: the cap stops the chain once \
             five URLs have been visited"
        );
    }

    /// A same-host, different-port redirect is a redirect to a different
    /// service. On loopback that is a different local process; on a hosted
    /// authorization server it is whatever else the operator runs on :8443.
    #[tokio::test]
    async fn the_client_does_not_follow_a_redirect_to_another_port() {
        let destination = serve(|_| ok_json(r#"{"marker":"followed"}"#)).await;
        let hop = format!("http://127.0.0.1:{}/elsewhere", destination.port);
        let origin = serve(move |_| redirect(302, &hop)).await;

        let http = ReqwestHttp::new().unwrap();
        let resp = http
            .get_json(&Url::parse(&format!("http://127.0.0.1:{}/start", origin.port)).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status, 302);
        assert_eq!(
            destination.hits(),
            0,
            "a redirect that only changes the port must not be followed"
        );
    }

    /// RFC 7231 §6.4.7: a 307 preserves the method **and the body**. On the
    /// token endpoint that body is the authorization code and the PKCE
    /// verifier, so following one hands both to whatever the `Location`
    /// names — including a same-origin path the authorization server never
    /// meant to receive them.
    #[tokio::test]
    async fn a_token_post_never_follows_a_redirect_even_within_one_origin() {
        let server = serve(|index| {
            if index == 0 {
                redirect(307, "/token-elsewhere")
            } else {
                ok_json(r#"{"access_token":"leaked"}"#)
            }
        })
        .await;

        let http = ReqwestHttp::new().unwrap();
        let resp = http
            .post_form(
                &Url::parse(&format!("http://127.0.0.1:{}/token", server.port)).unwrap(),
                &[
                    ("code".to_string(), "the-code".to_string()),
                    ("code_verifier".to_string(), "the-verifier".to_string()),
                ],
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status, 307,
            "the redirect must be surfaced as a failed exchange, not followed"
        );
        assert_eq!(server.hits(), 1, "{:?}", server.requests());
        assert!(
            !server.requests()[0].contains("/token-elsewhere"),
            "the code and verifier must never reach the redirect target"
        );
    }

    /// The same for dynamic client registration, which posts JSON.
    #[tokio::test]
    async fn a_registration_post_never_follows_a_redirect() {
        let server = serve(|index| {
            if index == 0 {
                redirect(308, "/register-elsewhere")
            } else {
                ok_json(r#"{"client_id":"leaked"}"#)
            }
        })
        .await;

        let http = ReqwestHttp::new().unwrap();
        let resp = http
            .post_json(
                &Url::parse(&format!("http://127.0.0.1:{}/register", server.port)).unwrap(),
                &serde_json::json!({"client_name": "Kunobi"}),
            )
            .await
            .unwrap();

        assert_eq!(resp.status, 308);
        assert_eq!(server.hits(), 1, "{:?}", server.requests());
    }
}

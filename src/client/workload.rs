//! The token a CI job or a pod presents to a Kunobi service, taken from its
//! platform without any secret configured by hand.
//!
//! First available wins:
//! 1. inside GitHub Actions, the job's OIDC ID token, requested for the
//!    audience the caller names (the job needs `id-token: write`);
//! 2. a GitLab CI ID token the pipeline put in `KUNOBI_ID_TOKEN`
//!    (`id_tokens:` in `.gitlab-ci.yml`, with the service's audience);
//! 3. a projected Kubernetes service-account token, read from the file named
//!    by `KUNOBI_SA_TOKEN_FILE` on every call, since the kubelet rotates it.
//!
//! A workload token goes only to a service reached over HTTPS or on this
//! machine: [`may_receive`] is checked before any source is read, so a
//! service URL taken from a project's configuration cannot collect one over
//! plain HTTP.
//!
//! Pass the service's own URL as the audience. A token minted for that
//! audience is useless to any other service that also trusts the issuer.

use anyhow::{Context, Result};
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where the Actions runtime serves ID tokens, and the bearer it takes.
pub const GITHUB_REQUEST_URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
pub const GITHUB_REQUEST_TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
/// A GitLab CI ID token minted for the service.
pub const ID_TOKEN_VAR: &str = "KUNOBI_ID_TOKEN";
/// The file holding a projected service-account token.
pub const SA_TOKEN_FILE_VAR: &str = "KUNOBI_SA_TOKEN_FILE";

/// A token is replaced this long before it expires, so a request in flight
/// does not carry one that lapses on arrival.
const EXPIRY_MARGIN: Duration = Duration::from_secs(60);

/// Which platform a token came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadKind {
    GitHubActions,
    GitLabCi,
    Kubernetes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadToken {
    pub kind: WorkloadKind,
    pub token: String,
    pub expires_at: SystemTime,
}

impl WorkloadToken {
    fn fresh_at(&self, now: SystemTime) -> bool {
        now + EXPIRY_MARGIN < self.expires_at
    }
}

/// What this process can use to get a workload token, read from its
/// environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkloadSources {
    /// The Actions runtime's ID token request URL and bearer.
    pub github: Option<(String, String)>,
    pub id_token: Option<String>,
    pub sa_token_file: Option<String>,
}

impl WorkloadSources {
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
        Self {
            github: var(GITHUB_REQUEST_URL).zip(var(GITHUB_REQUEST_TOKEN)),
            id_token: var(ID_TOKEN_VAR),
            sa_token_file: var(SA_TOKEN_FILE_VAR),
        }
    }

    /// Whether any source is present.
    pub fn any(&self) -> bool {
        self.github.is_some() || self.id_token.is_some() || self.sa_token_file.is_some()
    }
}

/// Workload tokens travel only over TLS, or to this machine.
pub fn may_receive(service_url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(service_url) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    }
}

static GITHUB_TOKENS: Mutex<Option<HashMap<String, WorkloadToken>>> = Mutex::new(None);

/// This process's workload token for the service at `service_url`, minted for
/// `audience`. `Ok(None)` when the service may not receive one or no source
/// is present.
pub async fn workload_token(service_url: &str, audience: &str) -> Result<Option<WorkloadToken>> {
    token_from(&WorkloadSources::from_env(), service_url, audience).await
}

/// [`workload_token`] with the sources given, not read from the environment.
pub async fn token_from(
    sources: &WorkloadSources,
    service_url: &str,
    audience: &str,
) -> Result<Option<WorkloadToken>> {
    if !may_receive(service_url) || !sources.any() {
        return Ok(None);
    }
    if let Some((url, request_token)) = &sources.github {
        return cached_github_token(url, request_token, audience)
            .await
            .map(Some);
    }
    if let Some(token) = &sources.id_token {
        return read_token(WorkloadKind::GitLabCi, token.trim()).map(Some);
    }
    if let Some(path) = &sources.sa_token_file {
        let token = std::fs::read_to_string(path)
            .with_context(|| format!("reading the service-account token at {path}"))?;
        return read_token(WorkloadKind::Kubernetes, token.trim()).map(Some);
    }
    Ok(None)
}

fn read_token(kind: WorkloadKind, token: &str) -> Result<WorkloadToken> {
    Ok(WorkloadToken {
        kind,
        expires_at: jwt_expiry(token)?,
        token: token.to_string(),
    })
}

async fn cached_github_token(
    request_url: &str,
    request_token: &str,
    audience: &str,
) -> Result<WorkloadToken> {
    let now = SystemTime::now();
    let cached = GITHUB_TOKENS
        .lock()
        .ok()
        .and_then(|cache| cache.as_ref()?.get(audience).cloned())
        .filter(|token| token.fresh_at(now));
    if let Some(cached) = cached {
        return Ok(cached);
    }
    let fresh = github_actions_token(request_url, request_token, audience).await?;
    if let Ok(mut cache) = GITHUB_TOKENS.lock() {
        cache
            .get_or_insert_with(HashMap::new)
            .insert(audience.to_string(), fresh.clone());
    }
    Ok(fresh)
}

/// Asks the Actions runtime for this job's OIDC ID token for `audience`.
pub async fn github_actions_token(
    request_url: &str,
    request_token: &str,
    audience: &str,
) -> Result<WorkloadToken> {
    #[derive(serde::Deserialize)]
    struct Response {
        value: String,
    }
    let mut url = reqwest::Url::parse(request_url).context("parsing the Actions ID token URL")?;
    url.query_pairs_mut().append_pair("audience", audience);
    let response: Response = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .get(url)
        .bearer_auth(request_token)
        .send()
        .await
        .context("requesting the GitHub Actions ID token")?
        .error_for_status()
        .context(
            "GitHub Actions refused the ID token request (does the job have `id-token: write`?)",
        )?
        .json()
        .await
        .context("decoding the GitHub Actions ID token response")?;
    read_token(WorkloadKind::GitHubActions, &response.value)
}

/// The `exp` of a JWT, read without verifying it: the token is ours to send,
/// not to trust, and only its lifetime matters here.
pub fn jwt_expiry(jwt: &str) -> Result<SystemTime> {
    let payload = jwt.split('.').nth(1).context("the token is not a JWT")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .context("the token's payload is not base64url")?;
    let claims: serde_json::Value =
        serde_json::from_slice(&bytes).context("the token's payload is not JSON")?;
    let exp = claims
        .get("exp")
        .and_then(serde_json::Value::as_u64)
        .context("the token has no numeric `exp`")?;
    Ok(UNIX_EPOCH + Duration::from_secs(exp))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "server", feature = "browser-login-core"))]
    use std::sync::Arc;
    #[cfg(any(feature = "server", feature = "browser-login-core"))]
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn jwt_with_exp(exp: u64) -> String {
        let encode = |value: serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        format!(
            "{}.{}.signature",
            encode(serde_json::json!({"alg": "RS256"})),
            encode(serde_json::json!({"exp": exp}))
        )
    }

    fn in_an_hour() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    #[cfg(any(feature = "server", feature = "browser-login-core"))]
    /// An Actions runtime stand-in: answers `token` when asked for
    /// `audience` with the right bearer, and counts the requests.
    async fn stub_github(token: String, audience: &'static str) -> (String, Arc<AtomicUsize>) {
        use axum::{Json, Router, extract::Query, http::HeaderMap, routing::get};
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = Router::new().route(
            "/token",
            get(
                move |Query(query): Query<HashMap<String, String>>, headers: HeaderMap| {
                    let token = token.clone();
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let authorized = headers
                            .get("authorization")
                            .is_some_and(|value| value == "Bearer runtime");
                        assert!(authorized, "the runtime bearer is sent");
                        assert_eq!(query.get("audience").map(String::as_str), Some(audience));
                        Json(serde_json::json!({"value": token}))
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, hits)
    }

    #[test]
    fn tokens_go_only_over_https_or_to_this_machine() {
        assert!(may_receive("https://kache.example.com"));
        assert!(may_receive("http://127.0.0.1:8080"));
        assert!(may_receive("http://localhost:8080/"));
        assert!(may_receive("http://[::1]:8080"));
        assert!(!may_receive("http://kache.example.com"));
        assert!(!may_receive("http://kache.ci.svc.cluster.local"));
        assert!(!may_receive("ftp://kache.example.com"));
        assert!(!may_receive("not a url"));
    }

    #[test]
    fn expiry_is_read_from_the_payload_and_a_non_jwt_is_refused() {
        assert_eq!(
            jwt_expiry(&jwt_with_exp(1_000)).unwrap(),
            UNIX_EPOCH + Duration::from_secs(1_000)
        );
        assert!(jwt_expiry("opaque").is_err());
        assert!(jwt_expiry("a.!!!.c").is_err());
        let no_exp = format!(
            "h.{}.s",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("{}")
        );
        assert!(jwt_expiry(&no_exp).is_err());
    }

    #[test]
    fn a_token_within_the_margin_of_expiry_is_not_fresh() {
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let token = |exp: u64| WorkloadToken {
            kind: WorkloadKind::GitHubActions,
            token: String::new(),
            expires_at: UNIX_EPOCH + Duration::from_secs(exp),
        };
        assert!(token(10_061).fresh_at(now));
        assert!(!token(10_060).fresh_at(now));
    }

    #[cfg(any(feature = "server", feature = "browser-login-core"))]
    #[tokio::test]
    async fn a_github_job_token_is_requested_for_the_audience_and_cached() {
        let jwt = jwt_with_exp(in_an_hour());
        let (url, hits) = stub_github(jwt.clone(), "https://cached.example.com").await;
        let sources = WorkloadSources {
            github: Some((url, "runtime".into())),
            ..Default::default()
        };
        for _ in 0..2 {
            let token = token_from(
                &sources,
                "https://kache.example.com",
                "https://cached.example.com",
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(token.kind, WorkloadKind::GitHubActions);
            assert_eq!(token.token, jwt);
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1, "the second call is cached");
    }

    #[cfg(any(feature = "server", feature = "browser-login-core"))]
    #[tokio::test]
    async fn nothing_is_read_for_a_service_that_may_not_receive_it() {
        let (url, hits) =
            stub_github(jwt_with_exp(in_an_hour()), "https://plain.example.com").await;
        let sources = WorkloadSources {
            github: Some((url, "runtime".into())),
            id_token: Some(jwt_with_exp(in_an_hour())),
            sa_token_file: Some("/nonexistent".into()),
        };
        let token = token_from(
            &sources,
            "http://kache.example.com",
            "https://plain.example.com",
        )
        .await
        .unwrap();
        assert_eq!(token, None);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        let none = token_from(
            &WorkloadSources::default(),
            "https://kache.example.com",
            "a",
        )
        .await
        .unwrap();
        assert_eq!(none, None);
    }

    #[tokio::test]
    async fn a_gitlab_id_token_is_used_as_given() {
        let jwt = jwt_with_exp(in_an_hour());
        let sources = WorkloadSources {
            id_token: Some(format!(" {jwt}\n")),
            sa_token_file: Some("/nonexistent".into()),
            ..Default::default()
        };
        let token = token_from(&sources, "https://kache.example.com", "kache")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((token.kind, token.token), (WorkloadKind::GitLabCi, jwt));
    }

    #[tokio::test]
    async fn a_service_account_token_is_read_from_its_file_each_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let sources = WorkloadSources {
            sa_token_file: Some(path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        for exp in [in_an_hour(), in_an_hour() + 60] {
            let jwt = jwt_with_exp(exp);
            std::fs::write(&path, format!("{jwt}\n")).unwrap();
            let token = token_from(&sources, "https://kache.example.com", "kache")
                .await
                .unwrap()
                .unwrap();
            assert_eq!((token.kind, token.token), (WorkloadKind::Kubernetes, jwt));
        }
        std::fs::remove_file(&path).unwrap();
        assert!(
            token_from(&sources, "https://kache.example.com", "kache")
                .await
                .is_err()
        );
    }

    #[test]
    fn sources_are_present_when_any_is_set() {
        assert!(!WorkloadSources::default().any());
        assert!(
            WorkloadSources {
                id_token: Some("t".into()),
                ..Default::default()
            }
            .any()
        );
        assert!(
            WorkloadSources {
                github: Some(("u".into(), "t".into())),
                ..Default::default()
            }
            .any()
        );
        assert!(
            WorkloadSources {
                sa_token_file: Some("f".into()),
                ..Default::default()
            }
            .any()
        );
    }
}

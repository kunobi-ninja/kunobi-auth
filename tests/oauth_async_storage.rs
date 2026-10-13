//! Awaited storage and the unchanged synchronous broker API.

#![cfg(feature = "oauth")]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use kunobi_auth::oauth::grant::NoDurableState;
use kunobi_auth::oauth::http_seam::FakeHttp;
use kunobi_auth::oauth::tokens::{MemoryTokenStore, now_unix};
use kunobi_auth::oauth::{
    AsyncRefreshBroker, AsyncRefreshBrokerConfig, AsyncTokenStore, AuthorizationServerMetadata,
    CredentialBroker, GrantHost, OAuthHttp, RefreshBroker, RefreshBrokerConfig, TokenEndpointAuth,
    TokenSet, TokenStore,
};
use tokio::sync::{Mutex, Notify, Semaphore};

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("controlled operation completed")
}

fn metadata() -> AuthorizationServerMetadata {
    AuthorizationServerMetadata {
        issuer: "https://auth.example.com".into(),
        authorization_endpoint: "https://auth.example.com/authorize".into(),
        token_endpoint: "https://auth.example.com/token".into(),
        registration_endpoint: None,
        scopes_supported: vec![],
        code_challenge_methods_supported: vec!["S256".into()],
        token_endpoint_auth_methods_supported: TokenEndpointAuth::Listed(vec!["none".into()]),
        grant_types_supported: vec![],
        revocation_endpoint: None,
    }
}

fn tokens(access: &str, expired: bool) -> TokenSet {
    TokenSet {
        access_token: access.into(),
        refresh_token: Some(format!("{access}-refresh")),
        expires_at: Some(now_unix() + if expired { -10 } else { 3600 }),
        scopes: vec!["read".into()],
    }
}

fn http() -> Arc<FakeHttp> {
    Arc::new(FakeHttp::default().with_post(
        "https://auth.example.com/token",
        FakeHttp::json(
            200,
            serde_json::json!({"access_token":"fresh", "refresh_token":"rotated", "expires_in":3600}),
        ),
    ))
}

struct Pause {
    armed: AtomicBool,
    entered: Notify,
    released: Semaphore,
}

impl Pause {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            armed: AtomicBool::new(true),
            entered: Notify::new(),
            released: Semaphore::new(0),
        })
    }

    async fn once(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.released.acquire().await.unwrap().forget();
        }
    }

    fn release(&self) {
        self.released.add_permits(1);
    }
}

struct HostStore {
    inner: MemoryTokenStore,
    load_pause: Option<Arc<Pause>>,
    save_pause: Option<Arc<Pause>>,
    fail_load: AtomicBool,
    fail_save: AtomicBool,
    save_attempts: AtomicUsize,
}

impl HostStore {
    fn new(set: TokenSet) -> Self {
        Self {
            inner: MemoryTokenStore::with("t1", set),
            load_pause: None,
            save_pause: None,
            fail_load: AtomicBool::new(false),
            fail_save: AtomicBool::new(false),
            save_attempts: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl AsyncTokenStore for HostStore {
    async fn load(&self, id: &str) -> anyhow::Result<Option<TokenSet>> {
        if let Some(pause) = &self.load_pause {
            pause.once().await;
        }
        tokio::task::yield_now().await;
        if self.fail_load.load(Ordering::SeqCst) {
            anyhow::bail!("storage unavailable");
        }
        self.inner.load(id)
    }

    async fn save(&self, id: &str, set: &TokenSet) -> anyhow::Result<()> {
        self.save_attempts.fetch_add(1, Ordering::SeqCst);
        if let Some(pause) = &self.save_pause {
            pause.once().await;
        }
        tokio::task::yield_now().await;
        if self.fail_save.load(Ordering::SeqCst) {
            anyhow::bail!("storage write unavailable");
        }
        self.inner.save(id, set)
    }

    async fn clear(&self, id: &str) -> anyhow::Result<()> {
        tokio::task::yield_now().await;
        self.inner.clear(id)
    }
}

fn config(
    store: Arc<dyn AsyncTokenStore>,
    http: Arc<dyn OAuthHttp>,
    commit_lock: Option<Arc<Mutex<()>>>,
) -> AsyncRefreshBrokerConfig {
    AsyncRefreshBrokerConfig {
        host: Arc::new(NoDurableState),
        connection_id: "t1".into(),
        store,
        http,
        metadata: metadata(),
        client_id: "cid".into(),
        client_secret: None,
        resource: Some("https://mcp.example.com/mcp".into()),
        scopes: vec!["read".into()],
        generation: 42,
        commit_lock,
    }
}

async fn progress_while_storage_is_pending() {
    let pause = Pause::new();
    let mut store = HostStore::new(tokens("live", false));
    store.load_pause = Some(pause.clone());
    let store = Arc::new(store);
    let http = http();
    let broker: Arc<dyn CredentialBroker> =
        Arc::new(AsyncRefreshBroker::new(config(store, http.clone(), None)));
    let call = tokio::spawn(async move { broker.access_token("ignored").await });
    bounded(pause.entered.notified()).await;

    // A response task on the same runtime can run while the RPC is pending.
    let progress = tokio::spawn(async { "host reply pump progressed" });
    assert_eq!(
        bounded(progress).await.unwrap(),
        "host reply pump progressed"
    );
    assert!(!call.is_finished());
    pause.release();
    assert_eq!(bounded(call).await.unwrap().unwrap(), "live");
    assert!(http.recorded_forms.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn delayed_host_storage_yields_on_a_current_thread_runtime() {
    progress_while_storage_is_pending().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn delayed_host_storage_yields_with_one_runtime_worker() {
    progress_while_storage_is_pending().await;
}

#[tokio::test]
async fn awaited_storage_keeps_expiry_refresh_single_flight_and_request_binding() {
    let store = Arc::new(HostStore::new(tokens("stale", true)));
    let http = http();
    let broker = Arc::new(AsyncRefreshBroker::new(config(
        store.clone(),
        http.clone(),
        None,
    )));
    let calls: Vec<_> = (0..8)
        .map(|_| {
            let broker = broker.clone();
            tokio::spawn(async move { broker.access_token("another-connection").await })
        })
        .collect();
    for call in calls {
        assert_eq!(bounded(call).await.unwrap().unwrap(), "fresh");
    }
    let forms = http.recorded_forms.lock().unwrap();
    assert_eq!(forms.len(), 1);
    assert!(forms[0].1.contains(&("client_id".into(), "cid".into())));
    assert!(
        forms[0]
            .1
            .contains(&("resource".into(), "https://mcp.example.com/mcp".into()))
    );
    assert!(forms[0].1.contains(&("scope".into(), "read".into())));
    assert_eq!(store.save_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .inner
            .load("t1")
            .unwrap()
            .unwrap()
            .refresh_token
            .as_deref(),
        Some("rotated")
    );
    assert!(store.inner.load("another-connection").unwrap().is_none());
}

#[tokio::test]
async fn a_failed_awaited_save_does_not_return_an_unstored_token_or_retry() {
    let original = tokens("stale", true);
    let store = Arc::new(HostStore::new(original.clone()));
    store.fail_save.store(true, Ordering::SeqCst);
    let http = http();
    let broker = AsyncRefreshBroker::new(config(store.clone(), http.clone(), None));
    let error = broker.refresh("t1").await.unwrap_err().to_string();
    assert!(error.contains("storage write unavailable"));
    assert_eq!(store.inner.load("t1").unwrap(), Some(original));
    assert_eq!(store.save_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(http.recorded_forms.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_failed_provider_refresh_never_attempts_an_async_storage_write() {
    let original = tokens("stale", true);
    let store = Arc::new(HostStore::new(original.clone()));
    let http = Arc::new(FakeHttp::default().with_post(
        "https://auth.example.com/token",
        FakeHttp::json(400, serde_json::json!({"error":"invalid_grant"})),
    ));
    let broker = AsyncRefreshBroker::new(config(store.clone(), http.clone(), None));
    assert!(broker.refresh("t1").await.is_err());
    assert_eq!(store.save_attempts.load(Ordering::SeqCst), 0);
    assert_eq!(store.inner.load("t1").unwrap(), Some(original));
    assert_eq!(http.recorded_forms.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn async_storage_forced_refresh_and_missing_refresh_keep_existing_semantics() {
    let store = Arc::new(HostStore::new(tokens("rejected-but-unexpired", false)));
    let http = http();
    let broker = AsyncRefreshBroker::new(config(store.clone(), http.clone(), None));
    assert_eq!(broker.refresh("t1").await.unwrap(), "fresh");
    assert_eq!(http.recorded_forms.lock().unwrap().len(), 1);

    let mut expired = tokens("stale", true);
    expired.refresh_token = None;
    store.save("t1", &expired).await.unwrap();
    assert!(
        broker
            .access_token("t1")
            .await
            .unwrap_err()
            .to_string()
            .contains("authorized again")
    );
    assert_eq!(http.recorded_forms.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn unavailable_storage_remains_distinct_from_a_missing_authorization() {
    let store = Arc::new(HostStore::new(tokens("live", false)));
    store.fail_load.store(true, Ordering::SeqCst);
    let http = http();
    let broker = AsyncRefreshBroker::new(config(store.clone(), http.clone(), None));
    let error = broker.access_token("t1").await.unwrap_err().to_string();
    assert!(error.contains("storage unavailable"));
    assert!(!error.contains("no stored authorization"));
    assert!(http.recorded_forms.lock().unwrap().is_empty());
    store.fail_load.store(false, Ordering::SeqCst);
    store.clear("t1").await.unwrap();
    assert!(
        broker
            .access_token("t1")
            .await
            .unwrap_err()
            .to_string()
            .contains("no stored authorization")
    );
}

async fn mutation_waits_for_refresh(replace: bool) {
    let pause = Pause::new();
    let mut store = HostStore::new(tokens("stale", true));
    store.save_pause = Some(pause.clone());
    let store = Arc::new(store);
    let lock = Arc::new(Mutex::new(()));
    let broker = Arc::new(AsyncRefreshBroker::new(config(
        store.clone(),
        http(),
        Some(lock.clone()),
    )));
    let refresh = tokio::spawn(async move { broker.refresh("t1").await });
    bounded(pause.entered.notified()).await;
    assert!(
        lock.try_lock().is_err(),
        "refresh retains the host commit fence across awaited save"
    );

    let mutation_started = Arc::new(Notify::new());
    let started = mutation_started.clone();
    let mutating = store.clone();
    let mutation = tokio::spawn(async move {
        started.notify_one();
        let _guard = lock.lock().await;
        if replace {
            mutating
                .save("t1", &tokens("successor", false))
                .await
                .unwrap();
        } else {
            mutating.clear("t1").await.unwrap();
        }
    });
    bounded(mutation_started.notified()).await;
    assert!(!mutation.is_finished());
    pause.release();
    assert_eq!(bounded(refresh).await.unwrap().unwrap(), "fresh");
    bounded(mutation).await.unwrap();
    let stored = store.inner.load("t1").unwrap();
    if replace {
        assert_eq!(stored.unwrap().access_token, "successor");
    } else {
        assert!(stored.is_none(), "a completed removal is not resurrected");
    }
}

#[tokio::test]
async fn replacement_cannot_be_overwritten_by_a_late_awaited_refresh_save() {
    mutation_waits_for_refresh(true).await;
}

#[tokio::test]
async fn removal_cannot_be_resurrected_by_a_late_awaited_refresh_save() {
    mutation_waits_for_refresh(false).await;
}

#[tokio::test]
async fn cancellation_before_storage_commit_releases_the_host_fence() {
    let pause = Pause::new();
    let mut store = HostStore::new(tokens("stale", true));
    store.save_pause = Some(pause.clone());
    let store = Arc::new(store);
    let lock = Arc::new(Mutex::new(()));
    let broker = Arc::new(AsyncRefreshBroker::new(config(
        store.clone(),
        http(),
        Some(lock.clone()),
    )));
    let refresh = tokio::spawn(async move { broker.refresh("t1").await });
    bounded(pause.entered.notified()).await;
    refresh.abort();
    assert!(bounded(refresh).await.unwrap_err().is_cancelled());
    let _guard = bounded(lock.lock()).await;
    store.clear("t1").await.unwrap();
    pause.release();
    assert!(store.inner.load("t1").unwrap().is_none());
    assert_eq!(store.save_attempts.load(Ordering::SeqCst), 1);
    // This models cancellation before a local commit. A dispatched host RPC
    // additionally needs the host's revision/incarnation fence, per trait docs.
}

#[derive(Default)]
struct ReauthHost(std::sync::Mutex<Vec<(String, u64, String)>>);

#[async_trait]
impl GrantHost for ReauthHost {
    async fn mark_needs_reauth(&self, id: &str, generation: u64, reason: &str) {
        self.0
            .lock()
            .unwrap()
            .push((id.into(), generation, reason.into()));
    }
}

#[tokio::test]
async fn async_reauth_observations_keep_the_constructed_connection_and_generation() {
    let host = Arc::new(ReauthHost::default());
    let mut cfg = config(
        Arc::new(HostStore::new(tokens("live", false))),
        http(),
        None,
    );
    cfg.host = host.clone();
    let broker = AsyncRefreshBroker::new(cfg);
    broker
        .mark_needs_reauth("successor-or-another-connection", "revoked")
        .await;
    assert_eq!(
        *host.0.lock().unwrap(),
        vec![("t1".into(), 42, "revoked".into())]
    );
}

#[tokio::test]
async fn the_one_x_config_and_mutable_public_fields_keep_their_existing_behavior() {
    let store: Arc<dyn TokenStore> = Arc::new(MemoryTokenStore::with("t1", tokens("old", false)));
    // Exhaustive literal, unchanged field types and non-generic constructor.
    let cfg: RefreshBrokerConfig = RefreshBrokerConfig {
        host: Arc::new(NoDurableState),
        connection_id: "t1".into(),
        store,
        http: http(),
        metadata: metadata(),
        client_id: "cid".into(),
        client_secret: None,
        resource: None,
        scopes: vec![],
        generation: 1,
        commit_lock: None,
    };
    let mut broker: RefreshBroker = RefreshBroker::new(cfg);
    let replacement: Arc<dyn TokenStore> =
        Arc::new(MemoryTokenStore::with("t2", tokens("replacement", true)));
    broker.connection_id = "t2".into();
    broker.store = replacement;
    broker.metadata = metadata();
    broker.metadata.token_endpoint = "https://auth.example.com/replacement-token".into();
    broker.http = Arc::new(FakeHttp::default().with_post(
        "https://auth.example.com/replacement-token",
        FakeHttp::json(
            200,
            serde_json::json!({"access_token":"from-replaced-http", "expires_in":3600}),
        ),
    ));
    let field: Arc<dyn TokenStore> = broker.store.clone();
    assert_eq!(
        field.load("t2").unwrap().unwrap().access_token,
        "replacement"
    );
    let broker: Arc<dyn CredentialBroker> = Arc::new(broker);
    assert_eq!(
        broker.access_token("untrusted-id").await.unwrap(),
        "from-replaced-http"
    );
}

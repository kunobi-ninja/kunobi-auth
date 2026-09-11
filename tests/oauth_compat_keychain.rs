//! Frozen on-disk credential identity.
//!
//! # Why these are integration tests and not `#[cfg(test)]` in `tokens.rs`
//!
//! An in-module test can be edited in the same commit, by the same hand, as the
//! constant it guards — which makes it a comment that compiles, not a guard. A
//! rename here fails a file that sits apart from the code and states, in its own
//! terms, why the value may not change.
//!
//! # What is at stake
//!
//! Nothing errors when a keychain account name or service changes. The load
//! simply finds no entry and returns `Ok(None)`. The gateway's
//! `restore_connections` reads that as "no token" and persists a
//! `needsReauthorization` flag, so the whole visible consequence of a one-word
//! rename is that every existing user is told to sign in again — with their
//! actual grant still sitting in the keychain under the old name, unreachable.
//!
//! These strings shipped. They are not ours to tidy.

#![cfg(feature = "oauth")]

use std::sync::{Arc, Mutex};

use kunobi_auth::oauth::tokens::{
    KeychainAccounts, KeychainTokenStore, SecretBackend, StoredAccess, TokenSet, TokenStore,
};

/// The gateway's prefix. Pinned here and in `extensions/kgw/src/oauth/tokens.rs`.
const KGW_PREFIX: &str = "mcp-target";

#[test]
fn gateway_account_names_are_frozen() {
    let accounts = KeychainAccounts::with_prefix(KGW_PREFIX);

    assert_eq!(
        accounts.access("t1"),
        "mcp-target/t1/oauth/access",
        "the access-token account name shipped; renaming it strands every \
         existing grant instead of failing"
    );
    assert_eq!(
        accounts.refresh("t1"),
        "mcp-target/t1/oauth/refresh",
        "the refresh-token account name shipped; see above"
    );
}

#[test]
fn accounts_do_not_collide_across_connections() {
    let accounts = KeychainAccounts::with_prefix(KGW_PREFIX);
    assert_ne!(accounts.access("t1"), accounts.access("t2"));
    assert_ne!(accounts.refresh("t1"), accounts.refresh("t2"));
    // The access and refresh halves of ONE connection must also differ, or a
    // save would overwrite one with the other.
    assert_ne!(accounts.access("t1"), accounts.refresh("t1"));
}

#[test]
fn oauth_accounts_do_not_collide_with_the_static_upstream_secret() {
    // The gateway stores a static upstream secret at `mcp-target/{id}/upstream`
    // (`extensions/kgw/src/credentials.rs`, `mcp_upstream_account`). An OAuth
    // account that collided with it would have the two credential kinds
    // silently overwriting each other on the same connection.
    let accounts = KeychainAccounts::with_prefix(KGW_PREFIX);
    let static_upstream = format!("{KGW_PREFIX}/t1/upstream");
    assert_ne!(accounts.access("t1"), static_upstream);
    assert_ne!(accounts.refresh("t1"), static_upstream);
}

#[test]
fn stored_access_envelope_shape_is_frozen() {
    let set = TokenSet {
        access_token: "at".into(),
        refresh_token: Some("rt".into()),
        expires_at: Some(1_800_000_000),
        scopes: vec!["read".into(), "write".into()],
    };

    let json = serde_json::to_value(StoredAccess::from(&set)).expect("envelope serialises");

    assert_eq!(json["access_token"], "at");
    assert_eq!(json["expires_at"], 1_800_000_000i64);
    assert_eq!(json["scopes"][0], "read");
    assert_eq!(json["scopes"][1], "write");
    assert!(
        json.get("refresh_token").is_none(),
        "the refresh token lives in its OWN keychain entry so it can be removed \
         when a server rotates or revokes it; folding it into this envelope \
         would make every existing entry unreadable AND lose that property"
    );
}

#[test]
fn an_envelope_written_before_scopes_existed_still_loads() {
    // `scopes` carries #[serde(default)] because envelopes predating it are on
    // disk. Dropping that attribute turns every one of them into an
    // "unreadable" error, which the gateway surfaces as a re-auth prompt.
    let legacy = r#"{"access_token":"at","expires_at":null}"#;
    let env: StoredAccess =
        serde_json::from_str(legacy).expect("a pre-scopes envelope still loads");
    assert_eq!(env.access_token, "at");
    assert!(env.scopes.is_empty());
}

/// Records every account name touched, so a round trip can assert on the exact
/// strings that reach the host's keychain.
#[derive(Default)]
struct SpyBackend {
    entries: Mutex<Vec<(String, String)>>,
    touched: Mutex<Vec<String>>,
}

impl SecretBackend for SpyBackend {
    fn get(&self, account: &str) -> anyhow::Result<Option<String>> {
        self.touched.lock().unwrap().push(account.to_string());
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .find(|(a, _)| a == account)
            .map(|(_, v)| v.clone()))
    }
    fn set(&self, account: &str, value: &str) -> anyhow::Result<()> {
        self.touched.lock().unwrap().push(account.to_string());
        let mut e = self.entries.lock().unwrap();
        e.retain(|(a, _)| a != account);
        e.push((account.to_string(), value.to_string()));
        Ok(())
    }
    fn remove(&self, account: &str) -> anyhow::Result<()> {
        self.touched.lock().unwrap().push(account.to_string());
        self.entries.lock().unwrap().retain(|(a, _)| a != account);
        Ok(())
    }
}

#[test]
fn a_round_trip_touches_exactly_the_frozen_account_names() {
    let spy = Arc::new(SpyBackend::default());
    let store = KeychainTokenStore::new(spy.clone(), KeychainAccounts::with_prefix(KGW_PREFIX));

    let set = TokenSet {
        access_token: "at".into(),
        refresh_token: Some("rt".into()),
        expires_at: Some(42),
        scopes: vec!["read".into()],
    };
    store.save("t1", &set).unwrap();
    let loaded = store.load("t1").unwrap().expect("saved token loads back");
    assert_eq!(loaded, set);

    let touched = spy.touched.lock().unwrap().clone();
    assert!(
        touched
            .iter()
            .all(|a| a.starts_with("mcp-target/t1/oauth/")),
        "the store reached outside its frozen namespace: {touched:?}"
    );
}

/// A backend that fails one named account's writes, to model a keychain that
/// refuses partway through a save.
struct FailsWriteTo {
    inner: SpyBackend,
    failing_account_suffix: &'static str,
}

impl SecretBackend for FailsWriteTo {
    fn get(&self, account: &str) -> anyhow::Result<Option<String>> {
        self.inner.get(account)
    }
    fn set(&self, account: &str, value: &str) -> anyhow::Result<()> {
        if account.ends_with(self.failing_account_suffix) {
            anyhow::bail!("keychain refused the write");
        }
        self.inner.set(account, value)
    }
    fn remove(&self, account: &str) -> anyhow::Result<()> {
        self.inner.remove(account)
    }
}

/// The failure that mixes two accounts' credentials.
///
/// A re-authorization that switches accounts writes a NEW access token and a
/// NEW refresh token. If the access write lands and the refresh write does not,
/// the connection holds account B's access token beside account A's refresh
/// token — it works now, and silently becomes a different identity at the first
/// refresh. Nothing surfaces it.
///
/// So a partial save must leave nothing LOADABLE. The user re-authorizes, which
/// is recoverable; a silent identity switch is not.
#[test]
fn a_partial_save_leaves_no_readable_credential_rather_than_a_mixed_pair() {
    let backend = Arc::new(FailsWriteTo {
        inner: SpyBackend::default(),
        failing_account_suffix: "/oauth/refresh",
    });
    let store = KeychainTokenStore::new(backend.clone(), KeychainAccounts::with_prefix(KGW_PREFIX));

    // Account A is signed in and working.
    let account_a = TokenSet {
        access_token: "A-access".into(),
        refresh_token: Some("A-refresh".into()),
        expires_at: None,
        scopes: vec![],
    };
    // Seed it through the spy directly, since the store cannot write refresh.
    backend
        .inner
        .set("mcp-target/t1/oauth/refresh", "A-refresh")
        .unwrap();
    backend
        .inner
        .set(
            "mcp-target/t1/oauth/access",
            &serde_json::to_string(&StoredAccess::from(&account_a)).unwrap(),
        )
        .unwrap();

    // Account B re-authorizes; the refresh write fails partway.
    let account_b = TokenSet {
        access_token: "B-access".into(),
        refresh_token: Some("B-refresh".into()),
        expires_at: None,
        scopes: vec![],
    };
    assert!(
        store.save("t1", &account_b).is_err(),
        "the save reported failure"
    );

    match store.load("t1").unwrap() {
        None => { /* fail-closed: the user re-authorizes */ }
        Some(loaded) => panic!(
            "a credential survived a partial save: access {:?} with refresh {:?} — if these \
             come from different accounts the connection silently switches identity on its \
             next refresh",
            loaded.access_token,
            loaded.refresh_token.as_deref().unwrap_or("<none>")
        ),
    }
}

#[test]
fn clearing_removes_both_halves() {
    // A clear that dropped only the access entry would leave a live refresh
    // token in the keychain after the user disconnected.
    let spy = Arc::new(SpyBackend::default());
    let store = KeychainTokenStore::new(spy.clone(), KeychainAccounts::with_prefix(KGW_PREFIX));

    store
        .save(
            "t1",
            &TokenSet {
                access_token: "at".into(),
                refresh_token: Some("rt".into()),
                expires_at: None,
                scopes: vec![],
            },
        )
        .unwrap();
    store.clear("t1").unwrap();

    assert!(
        spy.entries.lock().unwrap().is_empty(),
        "both halves cleared"
    );
    assert!(store.load("t1").unwrap().is_none());
}

#[test]
fn saving_without_a_refresh_token_removes_any_previous_one() {
    // A server that stops returning a refresh token must not leave the old one
    // behind, or a later refresh would replay a credential the server retired.
    let spy = Arc::new(SpyBackend::default());
    let store = KeychainTokenStore::new(spy.clone(), KeychainAccounts::with_prefix(KGW_PREFIX));

    store
        .save(
            "t1",
            &TokenSet {
                access_token: "at1".into(),
                refresh_token: Some("rt".into()),
                expires_at: None,
                scopes: vec![],
            },
        )
        .unwrap();
    store
        .save(
            "t1",
            &TokenSet {
                access_token: "at2".into(),
                refresh_token: None,
                expires_at: None,
                scopes: vec![],
            },
        )
        .unwrap();

    assert_eq!(store.load("t1").unwrap().unwrap().refresh_token, None);
    let entries = spy.entries.lock().unwrap();
    assert!(
        !entries.iter().any(|(a, _)| a.ends_with("/oauth/refresh")),
        "a stale refresh entry survived: {entries:?}"
    );
}

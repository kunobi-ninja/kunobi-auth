# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this crate adheres
to [SemVer](https://semver.org/) for the public API surface.

## [Unreleased]

## [0.3.0]

This release expands the OAuth2/OIDC surface and adds a server-side
DPoP verifier. Headless principals (Kubernetes operators, CI workers)
get a real login flow; the OAuth2 lifecycle is now closed at both ends
(login + revocation); access-token validation gets a fast path for
hot endpoints; bearer tokens become sender-constrainable.

### Added

- **OIDC Device Authorization Grant (RFC 8628)** — `oidc::begin_device_flow`,
  `oidc::begin_device_flow_with_url`, `AuthClient::begin_device_login`,
  `AuthClient::device_login`. Polling honours §3.5 (`authorization_pending`,
  `slow_down`, `expired_token`, `access_denied`). The returned ID token is
  validated against the IdP's JWKS before persistence.
- **Token introspection (RFC 7662)** — `oidc::introspect`,
  `AuthClient::introspect`. Returns the standard `IntrospectionResult`
  with `active`, `scope`, `client_id`, `exp`, etc.
- **Token revocation (RFC 7009)** — `oidc::revoke`,
  `AuthClient::logout_async`. Best-effort revocation at the IdP +
  local file removal. The synchronous `logout()` stays for callers
  that don't want network on the logout path.
- **`TokenKind`** enum (`Access` / `Refresh`) for the standard
  `token_type_hint` parameter on revoke/introspect.
- **`server::AuthLayer` / `AuthService`** — tower::Layer integration for
  `AuthnProvider`. `Router::new().layer(AuthLayer::required(provider))`
  inserts the validated `AuthIdentity` into request extensions; handlers
  retrieve it with `Extension<AuthIdentity>` and need no per-handler
  extractor type. `optional()` mode passes through missing headers.
- **`JwksManager::with_validation_cache(ttl)`** — opt-in per-token
  validated-claims cache, keyed by SHA-256 of the token. Per-entry
  lifetime is `min(token.exp, ttl)`. Bounded at 4096 entries with
  oldest-by-`valid_until` eviction. Trade-off: revoked tokens stay
  accepted up to `ttl` after revocation; pair with
  `oidc::introspect` if you need instant revocation.
- **DPoP server-side verifier (RFC 9449)** — `server::verify_dpop_proof`,
  `server::ath_for`, `server::jkt_thumbprint`, `server::cnf_jkt`,
  `server::DpopProof`. Verifies header (`typ=dpop+jwt`, `alg=ES256`,
  embedded `jwk` is EC P-256), signature, `htm`/`htu` match, `iat`
  skew, optional `ath` access-token binding, optional `cnf.jkt`
  thumbprint binding. Replay protection (`jti` tracking) is left to
  the existing `NonceTracker`.
- E2E test against Dex for the validation cache and introspection.

### Changed

- OIDC client now also sends RFC 8707 `resource` alongside Auth0-style
  `audience` on device + auth-code flows.

### Notes

- DPoP is server-side only in this release. Client-side DPoP (per-client
  keypair + per-request proof signing) is a follow-up; the design choices
  around key persistence and rotation warrant their own discussion.
- `oidc::revoke` returns `Err` when the IdP doesn't advertise
  `revocation_endpoint` in its discovery doc. Dex (≤ 2.41) doesn't
  implement RFC 7009; Keycloak/Okta/Auth0 do.

## [0.2.0]

### Breaking

- `JwksManager::validate_jwt` now requires an `issuer: &str` argument (third
  positional). Previously the issuer was not bound and an empty `audience`
  silently disabled `aud` validation. Both are now required and refuse empty
  values.

### Added — security

- **OIDC**: ID-token nonce is now verified on the auth-code response. The
  generated `Nonce` was previously discarded; tokens were accepted without
  binding to the originating session. The crate now validates signature, expiry,
  audience, issuer, and nonce before persisting any token.
- **OIDC refresh-token flow** (`oidc::refresh`, wired into `AuthClient::token`).
  Cached ID tokens past their expiry are silently exchanged for a fresh token;
  only failures fall through to interactive browser login. The crate now
  requests `offline_access` scope so providers actually issue refresh tokens.
- **JWKS hardening**: forced refetch when an unknown `kid` is presented, with a
  30-second cooldown to avoid amplifying garbage `kid`s into requests against
  the IdP. Added support for PS256/384/512, EdDSA, and OKP (Ed25519) JWKs.
- **SSH-signature replay**: `NonceTracker::check_and_insert` is now atomic
  under contention. The previous implementation used a read-then-write pattern
  that could let two concurrent requests with the same nonce both pass the
  freshness check.
- **Fingerprint redaction**: SSH-signature error responses now redact key
  fingerprints (`SHA256:01234567…`); full fingerprints remain in
  `tracing::warn!` logs for forensics.
- **TOFU store**: process-local `Mutex` around `verify`/`trust` to remove TOCTOU
  between concurrent calls. Atomic write via `tempfile::persist` (write to
  sibling temp + fsync + rename). `0o600` on the file, `0o700` on
  `~/.config/kunobi/`.
- **Token store**: same atomic-write + `0o700` directory treatment.

### Added — features

- `tempfile` is now a (feature-gated) dependency under `client` for atomic
  writes.
- E2E test suite (`tests/e2e_dex.rs`) against a real Dex instance; CI runs it
  in a dedicated `e2e` job.

### Changed

- `validate_jwt` now sets `validate_exp = true` and `validate_nbf = true`.
- The OIDC client now sends both `audience` (Auth0-style) and `resource`
  (RFC 8707) parameters when an audience is configured, for cross-IdP
  compatibility.

### Fixed

- Pre-existing clippy lints (`map_or` → `is_some_and`, needless lifetime in
  `extract_bearer_token`).
- Refreshed `Cargo.lock` to clear three known advisories:
  RUSTSEC-2026-0097/0098/0099/0104 (in `rand`, `rustls-webpki`) and the yanked
  `fastrand 2.4.0`. RUSTSEC-2023-0071 (`rsa` Marvin attack) remains unpatched
  upstream and is suppressed in CI's `cargo audit`.

[Unreleased]: https://github.com/kunobi-ninja/kunobi-auth/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kunobi-ninja/kunobi-auth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kunobi-ninja/kunobi-auth/releases/tag/v0.2.0

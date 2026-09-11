//! Provider-agnostic OAuth 2.0 access-token grants for Kunobi consumers.
//!
//! # Access-token grants
//!
//! Consumers that use provider APIs or remote MCP servers need an
//! authorization-code grant: discovery, consent, an expiring **access token**,
//! and refresh. This module centralizes that provider-agnostic machinery while
//! leaving each host responsible for its browser/UI, durable connection record,
//! keychain service identity, and credential injection.
//!
//! # Layering
//!
//! Each layer depends only on the ones above it, so a caller takes as much as it
//! needs and no more:
//!
//! | layer | modules | I/O |
//! |---|---|---|
//! | pure | [`crate::oauth::pkce`], [`crate::oauth::pure`] | none — build a request, parse a response |
//! | network seam | [`crate::oauth::http_seam`] | one trait, a real client and a scripted fake |
//! | protocol | [`crate::oauth::discovery`], [`crate::oauth::registration`] | through the seam only |
//! | grant | [`crate::oauth::flow`], [`crate::oauth::callback`], [`crate::oauth::tokens`] | the full authorization-code grant |
//! | orchestration | [`crate::oauth::grant`] | the fenced registry and single-flight refresh |
//!
//! The purity of the bottom layer is deliberate and inherited from
//! `kunobi-openapi`: everything there is testable with no network, no browser
//! and no real client id. The seam extends that property upward —
//! [`crate::oauth::http_seam::OAuthHttp`] is why candidate ordering, "404 means try the next
//! one", and the refusal of a confidential-only token endpoint are all verified
//! by unit tests rather than by a live server that may be down.
//!
//! # Why this is hand-rolled and not `rmcp`'s `auth` feature
//!
//! `rmcp` ships a complete OAuth client behind its `auth` feature. It was
//! evaluated and rejected, in descending weight:
//!
//! 1. **It authenticates an `rmcp` transport; these data paths are not one.**
//!    The gateway moves bytes with its own HTTP client through a credential
//!    injector, and a REST extension uses its own transport entirely. Only the
//!    token-acquisition half would be used.
//! 2. **`CredentialStore` is unkeyed.** One store holds one credential, so
//!    per-connection tokens mean one manager instance per connection plus a
//!    keychain-backed store — most of what would have been imported.
//! 3. **Feature unification reaches the embedded data plane.** `rmcp` is a
//!    dependency of upstream `agentgateway`; enabling `auth` changes what
//!    compiles into the in-process gateway for no benefit to it.
//! 4. **Two required behaviours need control it does not expose**: a pasted
//!    `client_id` with no registration step, and a *non-negotiable* loopback
//!    port (a pre-registered redirect URI must match exactly, so a random-port
//!    fallback silently breaks the flow).
//!
//! What was taken from `rmcp` is its discovery *ordering*, which is correct and
//! which a naive implementation gets wrong — see [`crate::oauth::discovery`].
//!
//! # Host responsibilities
//!
//! It obtains and refreshes a credential. It does not create an identity
//! boundary between the things that later use it. A host that shares one
//! authorized connection across several callers — as the gateway does across
//! agents — must say so in its own user-facing surfaces; scope minimisation
//! reduces the blast radius but does not partition it.

pub mod callback;
pub mod discovery;
pub mod flow;
pub mod grant;
pub mod http_seam;
pub mod pkce;
pub mod pure;
pub mod registration;
pub mod tokens;

pub use callback::{CallbackListener, CallbackResult, PortPolicy};
pub use discovery::{
    AuthorizationServerMetadata, ClientAuthMethod, ProtectedResourceMetadata, TokenEndpointAuth,
    authorization_server_metadata_urls, parse_www_authenticate_resource_metadata,
    protected_resource_metadata_urls,
};
pub use flow::{
    AuthorizeParams, DiscoveredAuth, ProviderResolution, authorization_url, authorization_url_with,
    exchange_code, minimal_scopes, refresh_token, resolve_provider,
};
pub use grant::{
    CredentialBroker, FlowId, GrantHost, GrantRegistry, PendingFlow, ReauthFlag, RefreshBroker,
    RefreshBrokerConfig, next_generation,
};
pub use http_seam::{JsonResponse, OAuthHttp, ReqwestHttp};
pub use pkce::{Pkce, constant_time_eq, generate_state, state_matches};
pub use registration::{ClientIdentity, register_public_client};
pub use tokens::{
    EXPIRY_SKEW_SECS, KeychainAccounts, KeychainTokenStore, SecretBackend, TokenSet, TokenStore,
    now_unix,
};

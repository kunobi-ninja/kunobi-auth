// Axum-free core — available without the `server` feature.
pub mod audit;
pub mod dpop;
pub mod jwks;
pub mod ssh;

// Axum/tower integration — only compiled with the `server` feature.
#[cfg(feature = "server")]
pub mod configured;
#[cfg(feature = "server")]
pub mod discovery;
#[cfg(feature = "server")]
pub mod layer;
#[cfg(feature = "mcp-server")]
pub mod mcp;
#[cfg(feature = "server")]
pub mod middleware;
#[cfg(feature = "server")]
pub mod observer;

pub use audit::{AuditLog, StdoutAuditLog};
#[cfg(feature = "server")]
pub use configured::{AuthBuilder, ConfiguredAuth, JwtAuthConfig, StaticTokenConfig};
#[cfg(feature = "server")]
pub use discovery::{
    KUNOBI_AUTH_DISCOVERY_PATH, kunobi_auth_discovery_router, kunobi_auth_discovery_router_at,
};
pub use dpop::{DpopProof, ath_for, cnf_jkt, jkt_thumbprint, verify_dpop_proof};
pub use jwks::{JwksManager, jwt_error_message, jwt_fail_reason, standard_jwks_url, verify_azp};
#[cfg(feature = "server")]
pub use layer::{AuthLayer, AuthService};
#[cfg(feature = "mcp-server")]
pub use mcp::{
    McpAuthLayer, McpAuthService, McpServerAuthConfig, McpServerAuthConfigError,
    McpWwwAuthenticate, OAUTH_PROTECTED_RESOURCE_PATH, ProtectedResourceMetadata,
    metadata_url_for_resource, protected_resource_metadata_router,
    protected_resource_metadata_router_at,
};
#[cfg(feature = "server")]
pub use middleware::{AuthnProvider, OptionalAuth, RequiredAuth};
#[cfg(feature = "server")]
pub use observer::{AuthEvent, AuthObserver};
pub use ssh::{
    CompiledSshProvider, NonceTracker, ParsedAuthorizedKey, SshSignatureHeader,
    build_signed_message, parse_ssh_auth_header, verify_ssh_signature,
    verify_ssh_signature_checked,
};

pub mod audit;
pub mod configured;
pub mod dpop;
pub mod jwks;
pub mod layer;
#[cfg(feature = "mcp-server")]
pub mod mcp;
pub mod middleware;
pub mod ssh;

pub use audit::{AuditLog, StdoutAuditLog};
pub use configured::{AuthBuilder, ConfiguredAuth, JwtAuthConfig, StaticTokenConfig};
pub use dpop::{DpopProof, ath_for, cnf_jkt, jkt_thumbprint, verify_dpop_proof};
pub use jwks::JwksManager;
pub use layer::{AuthLayer, AuthService};
#[cfg(feature = "mcp-server")]
pub use mcp::{
    McpAuthLayer, McpAuthService, McpServerAuthConfig, McpServerAuthConfigError,
    McpWwwAuthenticate, OAUTH_PROTECTED_RESOURCE_PATH, ProtectedResourceMetadata,
    metadata_url_for_resource, protected_resource_metadata_router,
    protected_resource_metadata_router_at,
};
pub use middleware::{AuthnProvider, OptionalAuth, RequiredAuth};
pub use ssh::{
    CompiledSshProvider, NonceTracker, ParsedAuthorizedKey, SshSignatureHeader,
    build_signed_message, parse_ssh_auth_header, verify_ssh_signature,
};

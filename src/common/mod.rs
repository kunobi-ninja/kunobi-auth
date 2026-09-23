//! Shared authn vocabulary: identities, errors, discovery, and claim rules.

/// Claim-matching primitives for authorization decisions.
pub mod authz;
/// Crypto-provider installation for `jsonwebtoken` backends.
pub mod crypto;
/// Auth-discovery wire shape shared by client and server.
pub mod discovery;
/// Top-level auth error type.
pub mod error;
/// Machine-readable auth-failure reasons.
pub mod fail;
/// Validated caller identity.
pub mod identity;
/// Declarative auth-method descriptors.
pub mod rules;
/// Constant-time secret comparison.
pub mod secret;
/// Service status-response wire shape.
pub mod status;
/// Workload-identity views over validated claims.
pub mod workload;

pub use authz::{ClaimAllowed, ClaimMatch, ClaimRule, first_match, first_rule_match};
pub use discovery::KunobiAuthDiscovery;
pub use error::AuthError;
pub use fail::AuthFailReason;
pub use identity::AuthIdentity;
pub use rules::{AuthMethod, OidcAuth, ServiceAccountAuth, TokenAuth};
pub use secret::secret_eq;
pub use status::{AuthMethodInfo, AuthStatus, Session, StatusResponse};
pub use workload::Workload;

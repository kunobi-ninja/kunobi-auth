use crate::common::AuthIdentity;

/// Optional auth identity -- None if no token provided, Some if authenticated.
#[derive(Debug, Clone)]
pub struct OptionalAuth(pub Option<AuthIdentity>);

/// Required auth identity -- returns 401 if not authenticated.
#[derive(Debug, Clone)]
pub struct RequiredAuth(pub AuthIdentity);

/// Axum layer placeholder -- actual implementation depends on the service.
/// Services provide their own middleware that uses JwksManager + PolicyEngine.
pub struct AuthLayer;

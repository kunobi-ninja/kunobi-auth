//! Authentication and authorization framework for Kunobi services.
//!
//! # Client usage (CLI, apps)
//! ```rust,no_run
//! use kunobi_auth::client::{AuthClient, ServiceConfig};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = ServiceConfig::discover("https://kobe.kunobi.ninja").await?;
//! let client = AuthClient::new(config)?;
//! let token = client.token().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Server usage (API services)
//! ```rust,no_run
//! use kunobi_auth::server::{PolicyEngine, JwksManager};
//! use kunobi_auth::common::AccessRule;
//! ```

pub mod common;

#[cfg(feature = "client")]
pub mod client;

pub mod server;

// Re-export common types at crate root
pub use common::{AccessRule, AuthError, AuthIdentity, AuthMethod, StatusResponse};

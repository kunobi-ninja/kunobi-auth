//! Grant orchestration: what happens around the protocol, not in it.
//!
//! [`crate::oauth::flow`] knows how to build an authorization URL and redeem a code.
//! This module knows the awkward part: that a grant takes minutes, that other
//! things happen during those minutes, and that finishing one is not a single
//! irreversible act but a sequence in which every step can be superseded.
//!
//! It lives in the crate rather than in a host because none of it is
//! provider-specific and all of it is easy to get subtly wrong — the fencing
//! and single-flight rules here are the accumulated fixes for observed defects,
//! documented at each site. A second host re-deriving them would re-derive the
//! bugs first.

pub mod broker;
pub mod host;
pub mod registry;

pub use broker::{CredentialBroker, RefreshBroker, RefreshBrokerConfig};
pub use host::{GrantHost, NoDurableState};
pub use registry::{FlowId, GrantRegistry, PendingFlow, ReauthFlag, next_generation};

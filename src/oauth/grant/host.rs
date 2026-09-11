//! The seam between grant machinery and whatever the host keeps on disk.

use async_trait::async_trait;

/// What a host must supply so grant machinery can outlive the process.
///
/// The registry's `needs_reauth` map is empty after a relaunch. That is fine for
/// a host with nothing durable, and wrong for one that has a record: a
/// connection whose grant was revoked would read back as healthy until some
/// caller's next real request happened to be rejected, and a status verb would
/// report a working connection the host has no evidence for.
///
/// So the durable mirror is a host responsibility, expressed here rather than
/// by this crate learning the shape of anyone's storage.
#[async_trait]
pub trait GrantHost: Send + Sync {
    /// Record — durably, if the host has anywhere durable — that this
    /// connection needs the user to authorize again.
    ///
    /// `generation` identifies the live resource that observed the failure. A
    /// host that keeps per-connection resources must drop an observation from a
    /// generation that is no longer current, or a late rejection from a
    /// replaced resource flags the grant that replaced it — see
    /// [`crate::oauth::grant::GrantRegistry::mark_needs_reauth_for_generation`].
    ///
    /// Deliberately returns nothing: this runs on failure paths that must not
    /// themselves be able to fail the operation that triggered them.
    async fn mark_needs_reauth(&self, connection_id: &str, generation: u64, reason: &str);
}

/// A host with nothing to persist. Useful in tests and for a host whose entire
/// state is the keychain.
pub struct NoDurableState;

#[async_trait]
impl GrantHost for NoDurableState {
    async fn mark_needs_reauth(&self, _connection_id: &str, _generation: u64, _reason: &str) {}
}

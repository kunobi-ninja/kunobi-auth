//! The fenced pending-flow registry.
//!
//! # What this is for
//!
//! An authorization grant needs a human in a browser, which can take minutes.
//! For that whole window the connection has a flow in flight, and the awkward
//! cases are all about a *second* thing happening during it: a second connect,
//! a disconnect, a removal, or the first flow finishing late after the user gave
//! up and started another.
//!
//! Every one of those was a real defect before the fencing here existed, and the
//! fixes are load-bearing rather than defensive. They are documented on each
//! method, because the reasons are not recoverable from the code.
//!
//! # Why the host owns the instance
//!
//! [`GrantRegistry`] is a plain type, not a process-global. The host declares
//! the global — the gateway keeps one in a `OnceLock` because its resolver
//! reaches it from three call paths whose signatures are shared with unrelated
//! code, and threading a registry through all of them would widen ~50 call
//! sites to carry a value one branch reads.
//!
//! # Why `live` is a type parameter rather than the host's own map
//!
//! It would be tidier for this crate to own only `pending` and `needs_reauth`
//! and leave the host's live resources alone. It would also be wrong.
//!
//! Four operations here span two or three maps under **one** lock acquisition,
//! and in each case that atomicity is the fix for a specific observed bug:
//! [`GrantRegistry::fail_pending`] and [`GrantRegistry::flow_status`] pair
//! `pending` with `needs_reauth`; [`GrantRegistry::install_for_flow`] checks the
//! `pending` fence and inserts into `live` and clears `needs_reauth`;
//! [`GrantRegistry::remove`] clears all three. Splitting the maps across two
//! locks reintroduces exactly the windows the fencing closed.
//!
//! So the registry owns all three, and `L` is whatever the host needs to keep
//! alive per connection — a running listener, a handle, or `()` for a host that
//! consumes credentials on demand and has nothing to keep.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::oauth::tokens::now_unix;

/// Source of instance generations.
///
/// A host that keeps a live resource per connection needs to answer "which
/// instance is this?" when a late observation arrives. Dropping a listener
/// handle stops its accept loop, but per-connection tasks it already spawned
/// hold their own reference and finish afterwards — so a request in flight when
/// a reconnect replaced the resource can still report a failure, keyed by a
/// connection id the *new* grant now answers to. During a reconnect the old
/// token is typically the revoked one, so that late rejection is not
/// hypothetical: it would flag the connection the user just repaired.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Mint a generation for a resource about to be built.
pub fn next_generation() -> u64 {
    NEXT_GENERATION.fetch_add(1, Ordering::Relaxed)
}

/// A started-but-unfinished authorization, surfaced by a status verb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingFlow {
    /// Empty between [`GrantRegistry::try_claim_pending`] and
    /// [`GrantRegistry::publish_pending`] — the window in which discovery is
    /// still running and no URL exists yet.
    pub authorization_url: String,
    /// The redirect URI the flow listens on.
    pub redirect_uri: String,
    /// Unix time the flow was claimed.
    pub started_at: i64,
}

/// Source of registry identities. See [`FlowId`].
static NEXT_REGISTRY: AtomicU64 = AtomicU64::new(1);

/// Identifies one authorization attempt, in one registry.
///
/// Every mutation of the pending slot after the claim is keyed on it, so a task
/// whose flow was abandoned and superseded cannot clear — or flag a failure
/// against — the attempt that replaced it. Without that, a browser closed at
/// minute one wipes the pending state of the retry started at minute six.
///
/// # Why it carries a registry identity
///
/// The sequence number alone is not enough once there is more than one
/// registry. Each instance starts its counter at 1, so two registries both mint
/// a first id that compares equal, and an id from one would pass the fence in
/// the other — letting a flow in extension A release, fail, or install against
/// extension B's flow of the same connection id.
///
/// That was unreachable while a single host owned the only registry, which is
/// exactly the assumption this crate exists to stop relying on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowId {
    registry: u64,
    seq: u64,
}

/// Why a connection needs the user to authorize again, and when that was seen.
///
/// Deliberately not the host's persisted record type: the host converts at its
/// own boundary, so this crate does not learn the shape of anyone's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReauthFlag {
    /// Why the connection needs the user to authorize again.
    pub reason: String,
    /// Unix time the failure was recorded.
    pub recorded_at: i64,
}

struct PendingEntry {
    id: FlowId,
    flow: PendingFlow,
}

struct LiveEntry<L> {
    resource: L,
    generation: u64,
}

/// Per-connection grant state: what is live, what is waiting on a browser, and
/// what has failed.
pub struct GrantRegistry<L> {
    /// Distinguishes this registry's [`FlowId`]s from any other's.
    id: u64,
    live: HashMap<String, LiveEntry<L>>,
    /// connection id → why the user must authorize again. This map is the
    /// in-process authority — it is the only home for a failure on a connection
    /// with no stored record at all — but it is empty after a relaunch, so a
    /// host with anywhere durable should mirror it. Without the mirror, a
    /// connection whose grant was revoked reads back as healthy until some
    /// caller's next real request happens to be rejected.
    needs_reauth: HashMap<String, ReauthFlag>,
    /// connection id → a flow that has been started and awaits its redirect.
    pending: HashMap<String, PendingEntry>,
    next_flow: u64,
}

impl<L> Default for GrantRegistry<L> {
    fn default() -> Self {
        Self {
            id: NEXT_REGISTRY.fetch_add(1, Ordering::Relaxed),
            live: HashMap::new(),
            needs_reauth: HashMap::new(),
            pending: HashMap::new(),
            next_flow: 1,
        }
    }
}

impl<L> GrantRegistry<L> {
    /// Claim the pending slot for `connection_id`.
    ///
    /// # Why a second connect is refused rather than cancelling the first
    ///
    /// Starting a second flow while one is in flight used to overwrite the slot,
    /// leaving the first task's listener bound and its port held for the whole
    /// consent timeout, with a client registered for each. A double-click was
    /// enough.
    ///
    /// Of the two safe answers — refuse the second, or cancel the first — this
    /// refuses. Cancelling would invalidate an authorization URL the user may
    /// already have open: their browser would redirect to a closed port and show
    /// a connection error with nothing to act on. Refusing hands back the URL
    /// that is already live, which is what a double-clicking user actually
    /// wants: the same consent, not a second one. It is also the cheaper of the
    /// two — the refusal lands before any listener is bound or client registered.
    ///
    /// That is why the error carries the existing [`PendingFlow`] rather than
    /// being a bare "busy": the caller is expected to return its URL.
    ///
    /// `now` is the caller's clock rather than one read here, so the staleness
    /// rule is testable without a clock seam. A claim older than `stale_after`
    /// is taken over unconditionally: that is the abandoned flow (browser
    /// closed, never completed), whose own callback timeout has by then released
    /// its listener. Nothing else expires the slot, so this is what stops an
    /// abandoned flow from blocking a legitimate retry forever.
    pub fn try_claim_pending(
        &mut self,
        connection_id: &str,
        now: i64,
        stale_after: Duration,
    ) -> Result<FlowId, PendingFlow> {
        if let Some(existing) = self.pending.get(connection_id)
            && now.saturating_sub(existing.flow.started_at) < stale_after.as_secs() as i64
        {
            return Err(existing.flow.clone());
        }
        let id = FlowId {
            registry: self.id,
            seq: self.next_flow,
        };
        self.next_flow += 1;
        self.pending.insert(
            connection_id.to_string(),
            PendingEntry {
                id,
                flow: PendingFlow {
                    authorization_url: String::new(),
                    redirect_uri: String::new(),
                    started_at: now,
                },
            },
        );
        Ok(id)
    }

    /// Publish the authorization URL once discovery has produced one.
    ///
    /// Ignored unless the claim is still ours, so a superseded attempt cannot
    /// hand the user a URL for a flow nothing is waiting on.
    pub fn publish_pending(
        &mut self,
        connection_id: &str,
        id: FlowId,
        authorization_url: String,
        redirect_uri: String,
    ) -> bool {
        match self.pending.get_mut(connection_id) {
            Some(entry) if entry.id == id => {
                entry.flow.authorization_url = authorization_url;
                entry.flow.redirect_uri = redirect_uri;
                true
            }
            _ => false,
        }
    }

    /// Whether `id` still holds the claim. The one question an in-flight task
    /// asks before doing anything irreversible.
    pub fn owns_pending(&self, connection_id: &str, id: FlowId) -> bool {
        self.pending.get(connection_id).is_some_and(|e| e.id == id)
    }

    /// Release a claim we still hold. `false` if it was taken from us.
    pub fn release_pending(&mut self, connection_id: &str, id: FlowId) -> bool {
        match self.pending.get(connection_id) {
            Some(entry) if entry.id == id => {
                self.pending.remove(connection_id);
                true
            }
            _ => false,
        }
    }

    /// Vacate the pending slot without recording a failure.
    ///
    /// For a user-initiated cancel, which is a different thing from a failure
    /// and from a disconnect:
    ///
    /// - [`Self::fail_pending`] records a reason, so the connection reports
    ///   `needsReauthorization`. Wrong here — the user said "never mind", and an
    ///   incumbent grant is still perfectly good.
    /// - [`Self::remove`] also drops the live resource and any recorded failure.
    ///   Wrong here for the same reason: cancelling a RECONNECT must leave the
    ///   grant already in place untouched.
    ///
    /// Unkeyed, because the person cancelling does not hold a [`FlowId`]. The
    /// abandoned attempt discovers it at its next fence and discards its own
    /// work rather than persisting it.
    ///
    /// Returns whether there was anything to abandon.
    pub fn abandon_pending(&mut self, connection_id: &str) -> bool {
        self.pending.remove(connection_id).is_some()
    }

    /// Fail a claim: release it **and** record why, in one lock acquisition.
    ///
    /// # Why this is not release-then-mark
    ///
    /// That is what it was, and the two steps took the lock separately. A status
    /// verb derives ONE state from `pending` and `needs_reauth` together, so a
    /// poll landing between them saw no pending flow and no recorded reason —
    /// which reads as "the browser leg ended without a grant": declined, or the
    /// window closed. A server that rejected the token exchange was therefore
    /// reported as the user's own cancellation, and the real reason — already
    /// computed, one statement away from being stored — was lost, because that
    /// state is terminal for a polling caller and nothing asks again.
    ///
    /// Atomicity alone fixes it: the only observable states become "still
    /// pending" and "failed, with the reason".
    pub fn fail_pending(&mut self, connection_id: &str, id: FlowId, reason: &str) -> bool {
        match self.pending.get(connection_id) {
            Some(entry) if entry.id == id => {
                self.pending.remove(connection_id);
                self.needs_reauth
                    .insert(connection_id.to_string(), flag(reason));
                true
            }
            _ => false,
        }
    }

    /// The pending flow and the recorded failure, read **together**.
    ///
    /// Reading them under two locks lets a transition happen in between and
    /// produces a state that was never true. This is the reader-side pair to
    /// [`Self::fail_pending`].
    pub fn flow_status(&self, connection_id: &str) -> (Option<PendingFlow>, Option<ReauthFlag>) {
        (
            self.pending.get(connection_id).map(|e| e.flow.clone()),
            self.needs_reauth.get(connection_id).cloned(),
        )
    }

    /// The pending flow alone.
    pub fn pending(&self, connection_id: &str) -> Option<PendingFlow> {
        self.pending.get(connection_id).map(|e| e.flow.clone())
    }

    /// The recorded failure reason alone.
    pub fn needs_reauth(&self, connection_id: &str) -> Option<String> {
        self.needs_reauth
            .get(connection_id)
            .map(|f| f.reason.clone())
    }

    /// Record, in memory, that a connection needs authorizing again.
    pub fn mark_needs_reauth(&mut self, connection_id: &str, reason: &str) {
        self.needs_reauth
            .insert(connection_id.to_string(), flag(reason));
    }

    /// Record a failure only if it came from the generation that is still live.
    ///
    /// Returns whether it was recorded. A late observation from a replaced
    /// resource is dropped rather than flagging the grant that replaced it.
    pub fn mark_needs_reauth_for_generation(
        &mut self,
        connection_id: &str,
        generation: u64,
        reason: &str,
    ) -> bool {
        let current = self.live.get(connection_id).map(|l| l.generation);
        if current != Some(generation) {
            return false;
        }
        self.needs_reauth
            .insert(connection_id.to_string(), flag(reason));
        true
    }

    /// The live resource for a connection, if one is running.
    pub fn live(&self, connection_id: &str) -> Option<&L> {
        self.live.get(connection_id).map(|l| &l.resource)
    }

    /// Install a live resource unconditionally.
    ///
    /// Returns whatever it displaced, so the caller drops it **after** releasing
    /// the lock. A host resource's destructor is arbitrary code — the gateway's
    /// merely signals a listener to stop, but one that reached back into the
    /// registry would deadlock against the guard still held here.
    ///
    /// Clearing `needs_reauth` is in-memory only, and the distinction matters
    /// for a host that also persists the flag: a restore path reaching this
    /// function proves a credential exists and a component came up, NOT that the
    /// provider still honours the grant. A host that mirrored this clear onto
    /// durable storage would erase, on the next launch, the very fact it
    /// persisted so a relaunch could not forget it.
    #[must_use = "the displaced resource must be dropped outside the lock"]
    pub fn install(&mut self, connection_id: &str, resource: L, generation: u64) -> Option<L> {
        let displaced = self.live.insert(
            connection_id.to_string(),
            LiveEntry {
                resource,
                generation,
            },
        );
        self.needs_reauth.remove(connection_id);
        displaced.map(|e| e.resource)
    }

    /// Install a live resource **only** if `id` still holds the pending claim.
    ///
    /// The fence and the install are one lock acquisition: a completion that
    /// lost its claim must not leave a resource behind for a grant that is no
    /// longer the current one.
    /// On refusal the resource comes back in `Err`, rather than being dropped
    /// here, for the same reason [`Self::install`] returns what it displaced.
    pub fn install_for_flow(
        &mut self,
        connection_id: &str,
        resource: L,
        id: FlowId,
        generation: u64,
    ) -> Result<Option<L>, L> {
        if !self.owns_pending(connection_id, id) {
            return Err(resource);
        }
        Ok(self.install(connection_id, resource, generation))
    }

    /// Drop a connection's live resource, and nothing else.
    ///
    /// The cleanup path for a flow that installed a resource and then found it
    /// must not keep it. [`Self::remove`] is the wrong tool there: it also
    /// clears `pending` unkeyed, so a completion tidying up after a **takeover**
    /// would destroy the slot of the very attempt that superseded it — the
    /// defect this fencing exists to prevent, reintroduced through the back
    /// door.
    #[must_use = "the removed resource must be dropped outside the lock"]
    pub fn remove_live(&mut self, connection_id: &str) -> Option<L> {
        self.live.remove(connection_id).map(|e| e.resource)
    }

    /// Forget a connection entirely.
    ///
    /// Clears `pending` unkeyed, and that is the point: this is only reached
    /// from a user-initiated destroy — a disconnect, or removing the connection
    /// — which is exactly the signal that an authorization still waiting on a
    /// browser should be abandoned. [`Self::owns_pending`] is how the abandoned
    /// flow finds out.
    #[must_use = "the removed resource must be dropped outside the lock"]
    pub fn remove(&mut self, connection_id: &str) -> Option<L> {
        let removed = self.live.remove(connection_id).map(|e| e.resource);
        self.needs_reauth.remove(connection_id);
        self.pending.remove(connection_id);
        removed
    }

    /// Drop all state. For tests.
    ///
    /// Deliberately does NOT rewind the flow counter. If it did, a test that
    /// claims, resets, then claims again would get the same [`FlowId`] twice,
    /// and a stale id would compare equal to a fresh one — quietly disarming
    /// every fence assertion that depends on the two differing.
    pub fn reset(&mut self) -> Vec<L> {
        let drained: Vec<L> = self.live.drain().map(|(_, e)| e.resource).collect();
        self.needs_reauth.clear();
        self.pending.clear();
        drained
    }
}

/// Stamp a reason with the moment it was observed.
///
/// Read here rather than taken from the caller because every caller would
/// otherwise pass `now_unix()` and one of them would eventually forget.
fn flag(reason: &str) -> ReauthFlag {
    ReauthFlag {
        reason: reason.to_string(),
        recorded_at: now_unix(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> GrantRegistry<&'static str> {
        GrantRegistry::default()
    }

    /// Long enough that no test crosses it by accident.
    const STALE_AFTER: Duration = Duration::from_secs(300);
    const T0: i64 = 1_000_000;

    /// Claim at `T0`, the common case.
    fn claim(r: &mut GrantRegistry<&'static str>, id: &str) -> FlowId {
        r.try_claim_pending(id, T0, STALE_AFTER)
            .expect("the slot was free")
    }

    #[test]
    fn a_second_claim_is_refused_and_hands_back_the_live_flow() {
        let mut r = reg();
        let first = claim(&mut r, "c1");
        r.publish_pending(
            "c1",
            first,
            "https://consent".into(),
            "http://127.0.0.1:9/cb".into(),
        );

        let refused = r
            .try_claim_pending("c1", T0 + 1, STALE_AFTER)
            .expect_err("a live claim is not taken over");
        assert_eq!(
            refused.authorization_url, "https://consent",
            "the refusal carries the URL already open in the user's browser, so a \
             double-click gets the SAME consent rather than a second one"
        );
    }

    /// The refusal must leave the incumbent INTACT, not merely return an error.
    ///
    /// Without this assertion, a refusal that deleted the incumbent's pending
    /// entry passed every other test in this module — verified by mutation. The
    /// user-visible effect would be that a double-click destroys the consent it
    /// was supposed to reuse.
    #[test]
    fn a_refused_claim_leaves_the_incumbent_owning_its_slot() {
        let mut r = reg();
        let first = claim(&mut r, "c1");
        let _ = r.try_claim_pending("c1", T0 + 1, STALE_AFTER);

        assert!(
            r.owns_pending("c1", first),
            "the incumbent still owns the slot"
        );
        assert!(
            r.publish_pending(
                "c1",
                first,
                "https://consent".into(),
                "http://127.0.0.1:9/cb".into()
            ),
            "and can still publish to it"
        );
    }

    /// A takeover is a different route to supersession than a `remove`, and the
    /// stale attempt must be just as powerless afterwards. Covered separately
    /// because the abandoned flow's own callback timeout fires around the same
    /// moment, so this is the ordering that actually happens in the field.
    #[test]
    fn an_attempt_superseded_by_takeover_can_neither_publish_nor_fail_its_successor() {
        let mut r = reg();
        let abandoned = claim(&mut r, "c1");
        let fresh = r
            .try_claim_pending("c1", T0 + STALE_AFTER.as_secs() as i64, STALE_AFTER)
            .expect("stale claim taken over");

        assert!(!r.publish_pending(
            "c1",
            abandoned,
            "https://stale".into(),
            "http://127.0.0.1:1/cb".into()
        ));
        assert!(!r.fail_pending("c1", abandoned, "browser closed"));
        assert_eq!(
            r.needs_reauth("c1"),
            None,
            "the abandoned attempt flagged nothing against the retry"
        );
        assert!(r.owns_pending("c1", fresh));
        assert_eq!(
            r.pending("c1").unwrap().authorization_url,
            "",
            "the retry's own slot is untouched"
        );
    }

    /// Two registries each mint a first id; neither may act on the other's flow.
    #[test]
    fn a_flow_id_from_another_registry_passes_no_fence() {
        let mut a = reg();
        let mut b = reg();
        let a_id = claim(&mut a, "shared");
        let b_id = claim(&mut b, "shared");

        assert_ne!(
            a_id, b_id,
            "ids are branded by the registry that minted them"
        );
        assert!(!b.owns_pending("shared", a_id));
        assert!(!b.release_pending("shared", a_id));
        assert!(!b.fail_pending("shared", a_id, "not yours"));
        assert!(
            b.owns_pending("shared", b_id),
            "B's own flow survived intact"
        );
        assert!(
            b.install_for_flow("shared", "resource", a_id, 1).is_err(),
            "and A cannot install into B"
        );
    }

    #[test]
    fn an_evicted_resource_is_handed_back_for_the_caller_to_drop() {
        // The caller drops it after releasing the lock; a destructor that
        // reached back into the registry would otherwise deadlock.
        let mut r = reg();
        let _ = r.install("c1", "first", 1);
        assert_eq!(r.install("c1", "second", 2), Some("first"));
        assert_eq!(r.remove_live("c1"), Some("second"));
        assert_eq!(r.remove_live("c1"), None);
    }

    #[test]
    fn an_abandoned_claim_is_taken_over_once_it_goes_stale() {
        let mut r = reg();
        let abandoned = claim(&mut r, "c1");

        let fresh = r
            .try_claim_pending("c1", T0 + STALE_AFTER.as_secs() as i64, STALE_AFTER)
            .expect("a stale claim does not block a retry forever");
        assert_ne!(
            abandoned, fresh,
            "the retry gets its own fence, so the abandoned flow finishing late \
             cannot act on it"
        );
        assert!(r.owns_pending("c1", fresh));
        assert!(!r.owns_pending("c1", abandoned));
    }

    #[test]
    fn staleness_is_measured_from_the_callers_clock() {
        // `now` is a parameter precisely so this is testable with no clock seam.
        let mut r = reg();
        claim(&mut r, "c1");
        assert!(
            r.try_claim_pending("c1", T0 + STALE_AFTER.as_secs() as i64 - 1, STALE_AFTER)
                .is_err(),
            "one second short of the threshold is still live"
        );
    }

    #[test]
    fn different_connections_do_not_share_the_pending_slot() {
        let mut r = reg();
        assert!(r.try_claim_pending("c1", T0, STALE_AFTER).is_ok());
        assert!(r.try_claim_pending("c2", T0, STALE_AFTER).is_ok());
    }

    #[test]
    fn a_superseded_attempt_cannot_release_its_successors_claim() {
        let mut r = reg();
        let first = claim(&mut r, "c1");
        let _ = r.remove("c1"); // user disconnected, abandoning the flow
        let second = claim(&mut r, "c1");

        assert!(!r.release_pending("c1", first), "the stale id owns nothing");
        assert!(
            r.owns_pending("c1", second),
            "the retry's claim survived the abandoned attempt's cleanup"
        );
    }

    #[test]
    fn a_superseded_attempt_cannot_flag_its_successor() {
        let mut r = reg();
        let first = claim(&mut r, "c1");
        let _ = r.remove("c1");
        let second = claim(&mut r, "c1");

        assert!(!r.fail_pending("c1", first, "browser closed"));
        assert_eq!(
            r.needs_reauth("c1"),
            None,
            "the abandoned attempt recorded nothing against the live one"
        );
        assert!(r.owns_pending("c1", second));
    }

    #[test]
    fn failing_releases_and_records_together() {
        let mut r = reg();
        let id = claim(&mut r, "c1");
        assert!(r.fail_pending("c1", id, "token endpoint said invalid_grant"));

        let (pending, flag) = r.flow_status("c1");
        assert!(pending.is_none(), "the slot was released");
        assert_eq!(
            flag.expect("the reason was recorded in the same lock")
                .reason,
            "token endpoint said invalid_grant",
            "a reader can never see 'no pending flow AND no reason', which would \
             be indistinguishable from the user cancelling"
        );
    }

    #[test]
    fn publishing_is_ignored_once_the_claim_is_lost() {
        let mut r = reg();
        let first = claim(&mut r, "c1");
        let _ = r.remove("c1");
        claim(&mut r, "c1");

        assert!(!r.publish_pending(
            "c1",
            first,
            "https://stale".into(),
            "http://127.0.0.1:1/cb".into()
        ));
        assert_eq!(
            r.pending("c1").unwrap().authorization_url,
            "",
            "the live attempt still has no URL of its own"
        );
    }

    #[test]
    fn install_for_flow_refuses_once_the_claim_is_lost() {
        let mut r = reg();
        let first = claim(&mut r, "c1");
        let _ = r.remove("c1");
        let second = claim(&mut r, "c1");

        assert!(
            r.install_for_flow("c1", "stale", first, 1).is_err(),
            "a refused install hands the resource back rather than dropping it under the lock"
        );
        assert!(r.live("c1").is_none(), "no resource left behind");
        assert!(r.install_for_flow("c1", "fresh", second, 2).is_ok());
        assert_eq!(r.live("c1"), Some(&"fresh"));
    }

    #[test]
    fn installing_clears_a_previous_failure() {
        let mut r = reg();
        r.mark_needs_reauth("c1", "revoked");
        let id = claim(&mut r, "c1");
        assert!(r.install_for_flow("c1", "live", id, 1).is_ok());
        assert_eq!(
            r.needs_reauth("c1"),
            None,
            "a successful authorization clears the reason the user just fixed"
        );
    }

    #[test]
    fn a_replaced_generation_cannot_flag_the_grant_that_replaced_it() {
        let mut r = reg();
        let _ = r.install("c1", "gen1", 1);
        let _ = r.install("c1", "gen2", 2);

        assert!(
            !r.mark_needs_reauth_for_generation("c1", 1, "late 401 from the old injector"),
            "the old generation's late observation is dropped"
        );
        assert_eq!(r.needs_reauth("c1"), None);

        assert!(r.mark_needs_reauth_for_generation("c1", 2, "really revoked"));
        assert_eq!(r.needs_reauth("c1").as_deref(), Some("really revoked"));
    }

    #[test]
    fn remove_live_leaves_the_pending_slot_alone() {
        let mut r = reg();
        let id = claim(&mut r, "c1");
        let _ = r.install_for_flow("c1", "live", id, 1);
        let _ = r.remove_live("c1");

        assert!(r.live("c1").is_none());
        assert!(
            r.owns_pending("c1", id),
            "tidying up a resource must not destroy the attempt that owns the slot"
        );
    }

    #[test]
    fn abandoning_vacates_the_slot_without_recording_a_failure() {
        let mut r = reg();
        let flow = claim(&mut r, "c1");
        r.mark_needs_reauth("c1", "an earlier, unrelated failure");

        assert!(r.abandon_pending("c1"));

        assert!(
            !r.owns_pending("c1", flow),
            "the abandoned attempt lost its claim"
        );
        assert_eq!(
            r.needs_reauth("c1").as_deref(),
            Some("an earlier, unrelated failure"),
            "cancelling records nothing of its own, and disturbs nothing already recorded"
        );
    }

    #[test]
    fn abandoning_leaves_an_incumbent_grant_alone() {
        // Cancelling a RECONNECT must not cost the user the grant they already
        // had — the difference between this and `remove`.
        let mut r = reg();
        let first = claim(&mut r, "c1");
        let _ = r.install_for_flow("c1", "incumbent", first, 1);
        // The first attempt finished and released its slot; a RECONNECT then
        // claims it again.
        r.release_pending("c1", first);
        claim(&mut r, "c1");

        assert!(r.abandon_pending("c1"));
        assert_eq!(r.live("c1"), Some(&"incumbent"));
    }

    #[test]
    fn abandoning_nothing_says_so() {
        let mut r = reg();
        assert!(!r.abandon_pending("never-started"));
    }

    #[test]
    fn remove_clears_everything_including_an_unkeyed_pending_slot() {
        let mut r = reg();
        let id = claim(&mut r, "c1");
        let _ = r.install_for_flow("c1", "live", id, 1);
        r.mark_needs_reauth("c1", "x");
        let _ = r.remove("c1");

        assert!(r.live("c1").is_none());
        assert!(r.pending("c1").is_none());
        assert_eq!(r.needs_reauth("c1"), None);
        assert!(
            !r.owns_pending("c1", id),
            "the abandoned flow can discover it was destroyed"
        );
    }

    #[test]
    fn resetting_does_not_rewind_the_flow_counter() {
        // If it did, a stale id would compare equal to a fresh one and every
        // fence assertion built on the two differing would quietly pass.
        let mut r = reg();
        let before = claim(&mut r, "c1");
        let _ = r.reset();
        let after = claim(&mut r, "c1");
        assert_ne!(before, after);
    }

    #[test]
    fn generations_are_unique_and_increasing() {
        let a = next_generation();
        let b = next_generation();
        assert!(b > a);
    }
}

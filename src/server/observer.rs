//! Pluggable observation of authentication outcomes.
//!
//! [`AuthObserver`] is a thin hook the server-side auth pipeline calls on every
//! authentication attempt, handing it an [`AuthEvent`]. The crate ships no
//! implementation and emits no telemetry of its own — you register an observer
//! via [`AuthBuilder::observer`](crate::server::AuthBuilder::observer) and turn
//! the events into whatever telemetry you use: Prometheus counters keyed by
//! [`AuthFailReason::label`], structured logs, audit trails, tracing spans, …
//!
//! This mirrors the [`AuditLog`](crate::server::AuditLog) hook but is scoped to
//! *authentication* (credential accept/reject) rather than *authorization*
//! decisions, and carries a typed [`AuthFailReason`] for low-cardinality
//! metrics.

use crate::common::{AuthFailReason, AuthIdentity};

/// The outcome of a single authentication attempt, handed to an
/// [`AuthObserver`].
///
/// `#[non_exhaustive]`: match with a `_` arm so new event kinds can be added in
/// a future release without breaking your observer. The `'a` lifetime lets the
/// pipeline lend borrowed context (the resolved identity, the provider name)
/// without cloning on the hot path.
#[non_exhaustive]
#[derive(Debug)]
pub enum AuthEvent<'a> {
    /// A credential was accepted. `identity` carries the resolved provider,
    /// method, and claims (read `identity.provider` / `identity.method` for
    /// success labels).
    Success { identity: &'a AuthIdentity },
    /// A credential was rejected, or a provider failed.
    ///
    /// `provider` is the configured provider name when the failure is
    /// attributable to one, else `None` (e.g. a multi-issuer fall-through where
    /// no single provider "owns" the rejection). `reason` is a bounded,
    /// redaction-safe classification suitable for a metrics label
    /// ([`AuthFailReason::label`]).
    Failure {
        provider: Option<&'a str>,
        reason: AuthFailReason,
    },
}

/// A hook invoked on every authentication attempt.
///
/// Register one with [`AuthBuilder::observer`](crate::server::AuthBuilder::observer).
/// `observe` is called **synchronously on the auth hot path**, so an
/// implementation must be cheap and non-blocking — increment a counter, enqueue
/// a record, emit a log line. Do not perform blocking I/O or `.await` inside it;
/// hand off to a background task/channel if you need to.
pub trait AuthObserver: Send + Sync {
    /// Observe a single authentication outcome. Must not block.
    fn observe(&self, event: AuthEvent<'_>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A captured event as a `(kind, provider, reason_label)` tuple.
    type RecordedEvent = (&'static str, Option<String>, Option<&'static str>);

    /// A recording observer for tests/examples.
    #[derive(Default)]
    struct Recorder {
        events: Mutex<Vec<RecordedEvent>>,
    }

    impl AuthObserver for Recorder {
        fn observe(&self, event: AuthEvent<'_>) {
            let row = match event {
                AuthEvent::Success { identity } => {
                    ("success", Some(identity.provider.clone()), None)
                }
                AuthEvent::Failure { provider, reason } => (
                    "failure",
                    provider.map(str::to_string),
                    Some(reason.label()),
                ),
            };
            self.events.lock().unwrap().push(row);
        }
    }

    #[test]
    fn recorder_captures_success_and_failure() {
        let rec = Recorder::default();
        let identity = AuthIdentity {
            provider: "dev".into(),
            identity: "alice".into(),
            method: "token".into(),
            claims: Default::default(),
        };
        rec.observe(AuthEvent::Success {
            identity: &identity,
        });
        rec.observe(AuthEvent::Failure {
            provider: Some("oidc"),
            reason: AuthFailReason::Expired,
        });
        rec.observe(AuthEvent::Failure {
            provider: None,
            reason: AuthFailReason::NoMatchingProvider,
        });

        let events = rec.events.lock().unwrap();
        assert_eq!(events[0], ("success", Some("dev".to_string()), None));
        assert_eq!(
            events[1],
            ("failure", Some("oidc".to_string()), Some("expired"))
        );
        assert_eq!(events[2], ("failure", None, Some("no_matching_provider")));
    }
}

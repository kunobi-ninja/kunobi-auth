use crate::common::AuthIdentity;

/// Audit log entry.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub identity: Option<AuthIdentity>,
    pub action: String,
    pub resource: String,
    pub outcome: AuditOutcome,
}

#[derive(Debug, Clone)]
pub enum AuditOutcome {
    Allowed,
    Denied(String),
    Error(String),
}

/// Trait for audit logging. Implement for your storage backend.
pub trait AuditLog: Send + Sync {
    fn log(&self, entry: AuditEntry);
}

/// Simple stdout audit logger.
pub struct StdoutAuditLog;

impl AuditLog for StdoutAuditLog {
    fn log(&self, entry: AuditEntry) {
        let identity = entry
            .identity
            .map(|i| i.identity)
            .unwrap_or_else(|| "anonymous".to_string());
        tracing::info!(
            identity = %sanitize(&identity),
            action = %sanitize(&entry.action),
            resource = %sanitize(&entry.resource),
            outcome = ?entry.outcome,
            "audit"
        );
    }
}

/// Replace control characters (newlines, ANSI escape introducers, …) with
/// U+FFFD. The identity typically derives from an IdP claim an attacker can
/// choose, so raw control characters would let them forge audit lines or
/// corrupt terminal output under a plain-text subscriber.
fn sanitize(field: &str) -> std::borrow::Cow<'_, str> {
    if field.chars().any(char::is_control) {
        std::borrow::Cow::Owned(
            field
                .chars()
                .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_entry(identity: Option<AuthIdentity>) -> AuditEntry {
        AuditEntry {
            timestamp: chrono::Utc::now(),
            identity,
            action: "read".to_string(),
            resource: "/v1/pods".to_string(),
            outcome: AuditOutcome::Allowed,
        }
    }

    #[test]
    fn test_audit_entry_construction() {
        let entry = sample_entry(None);
        assert_eq!(entry.action, "read");
        assert_eq!(entry.resource, "/v1/pods");
        assert!(entry.identity.is_none());
        matches!(entry.outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn test_audit_entry_with_identity() {
        let id = AuthIdentity {
            provider: "oidc".to_string(),
            identity: "user@example.com".to_string(),
            method: "oidc".to_string(),
            claims: HashMap::new(),
        };
        let entry = sample_entry(Some(id));
        assert!(entry.identity.is_some());
        assert_eq!(entry.identity.unwrap().identity, "user@example.com");
    }

    #[test]
    fn test_audit_outcome_variants() {
        let allowed = AuditOutcome::Allowed;
        let denied = AuditOutcome::Denied("no permission".to_string());
        let error = AuditOutcome::Error("internal failure".to_string());

        // Just verify they can be constructed and debug-printed
        let _ = format!("{:?}", allowed);
        let _ = format!("{:?}", denied);
        let _ = format!("{:?}", error);
    }

    #[test]
    fn test_stdout_audit_log_does_not_panic() {
        let logger = StdoutAuditLog;
        // Log with identity
        let id = AuthIdentity {
            provider: "p".to_string(),
            identity: "user".to_string(),
            method: "oidc".to_string(),
            claims: HashMap::new(),
        };
        logger.log(sample_entry(Some(id)));

        // Log without identity (anonymous)
        logger.log(sample_entry(None));
    }

    #[test]
    fn sanitize_replaces_control_characters() {
        let forged = "alice\n2026-08-07 INFO audit identity=admin outcome=Allowed";
        let clean = sanitize(forged);
        assert!(!clean.contains('\n'), "newline must not survive: {clean:?}");
        assert!(clean.contains('\u{FFFD}'));
        // ANSI escape introducer is a control character too.
        assert_eq!(sanitize("a\x1b[31mred"), "a\u{FFFD}[31mred");
        // Clean strings pass through unchanged (borrowed).
        assert!(matches!(
            sanitize("user@example.com"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn test_audit_entry_denied_outcome() {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            identity: None,
            action: "write".to_string(),
            resource: "/v1/secrets".to_string(),
            outcome: AuditOutcome::Denied("forbidden".to_string()),
        };
        assert_eq!(entry.action, "write");
        matches!(entry.outcome, AuditOutcome::Denied(ref msg) if msg == "forbidden");
    }

    #[test]
    fn test_audit_entry_error_outcome() {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            identity: None,
            action: "delete".to_string(),
            resource: "/v1/deployments".to_string(),
            outcome: AuditOutcome::Error("timeout".to_string()),
        };
        matches!(entry.outcome, AuditOutcome::Error(ref msg) if msg == "timeout");
    }
}

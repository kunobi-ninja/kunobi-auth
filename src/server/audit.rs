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
            identity = %identity,
            action = %entry.action,
            resource = %entry.resource,
            outcome = ?entry.outcome,
            "audit"
        );
    }
}

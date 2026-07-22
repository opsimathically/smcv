use std::time::SystemTime;

use crate::{DomainResult, ObjectId, PrincipalId, RequestId};

/// Supplies cryptographically secure random bytes.
pub trait EntropySource: Send + Sync {
    /// Fills the complete destination or returns an unavailable error.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying CSPRNG cannot fill the destination.
    fn fill(&self, destination: &mut [u8]) -> DomainResult<()>;
}

/// Supplies wall-clock time through an injectable boundary.
pub trait Clock: Send + Sync {
    /// Returns the current wall-clock time.
    fn now(&self) -> SystemTime;
}

/// A secret-free audit event accepted by the audit boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Correlates the event with one request.
    pub request_id: RequestId,
    /// Identifies the acting principal when known.
    pub principal_id: Option<PrincipalId>,
    /// Uses a closed, non-secret action vocabulary.
    pub action: &'static str,
    /// References an opaque target only.
    pub target_id: Option<ObjectId>,
    /// Records the authorization or operation outcome.
    pub outcome: &'static str,
}

/// Persists security audit events.
pub trait AuditSink: Send + Sync {
    /// Records one event or fails the protected operation closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the event cannot be durably recorded.
    fn record(&self, event: &AuditEvent) -> DomainResult<()>;
}

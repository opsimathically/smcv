#![forbid(unsafe_code)]
#![doc = "Security-sensitive domain types and ports for SMCV."]

mod authorization;
mod error;
mod ids;
mod lifecycle;
mod ports;
mod secret;

pub use authorization::{Action, GrantSpec, ResourceKind};
pub use error::{DomainError, DomainResult};
pub use ids::{
    AuditEventId, AuthenticatorId, CeremonyId, CredentialId, GrantId, InstallationId,
    MaintenanceJobId, NamespaceId, ObjectId, PolicyId, PrincipalId, RequestId, SecretId, SessionId,
    VaultId,
};
pub use lifecycle::SecretSchedule;
pub use ports::{AuditEvent, AuditSink, Clock, EntropySource};
pub use secret::{ProtectedBytes, ProtectedString};

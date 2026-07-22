#![forbid(unsafe_code)]
#![doc = "Security-sensitive domain types and ports for SMCV."]

mod error;
mod ids;
mod ports;
mod secret;

pub use error::{DomainError, DomainResult};
pub use ids::{InstallationId, NamespaceId, ObjectId, PrincipalId, RequestId, SecretId, VaultId};
pub use ports::{AuditEvent, AuditSink, Clock, EntropySource};
pub use secret::{ProtectedBytes, ProtectedString};

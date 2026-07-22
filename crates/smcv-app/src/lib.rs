#![forbid(unsafe_code)]
#![doc = "Application-service coordination for SMCV."]
#![cfg_attr(test, allow(clippy::panic))]

use std::{fmt, net::SocketAddr, path::PathBuf, time::Duration};

use thiserror::Error;

pub use smcv_core::SecretSchedule;

mod authentication;
mod authorization;
mod authorized_vault;
mod backup;
mod initialization;
mod passkeys;
mod rotation;
mod service_identity;
mod vault_core;

pub use authentication::{
    AuthenticatedOwner, AuthenticationError, BrowserSessionSecrets, LocalSetupCapability,
};
pub use authorization::{
    AuthorizationError, EffectiveAccessDelta, PolicyDetails, PolicyMetadata, RequestPrincipal,
};
pub use authorized_vault::{AuthorizedVault, AuthorizedVaultError, IdempotencyInput};
pub use backup::{BackupError, BackupFileReport, CredentialRestoreMode, RestoreReport};
pub use initialization::{InitializationError, InitializedVault, initialize_vault};
pub use passkeys::{PasskeyChallenge, PasskeyService};
pub use rotation::{RootRotationOutcome, RotationProgress};
pub use service_identity::{
    ApplicationCredentialSummary, AuthenticatedService, IssuedApplicationCredential,
    ServiceIdentityMetadata,
};
pub use vault_core::{
    AuditVerification, DecryptedMetadata, DueSecret, MetadataInput, NamespaceListItem,
    OwnerPurgeApproval, SecretCreated, SecretListItem, SecretVersionSummary, VaultError,
    VaultOperationContext,
};

/// Safe build information exposed by diagnostics and health adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildInfo {
    /// Package version compiled into the binary.
    pub version: &'static str,
}

impl BuildInfo {
    /// Returns build information for this workspace version.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

/// How secure transport reaches the SMCV HTTP listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportMode {
    /// Explicit local-only HTTP for development and local recovery.
    LoopbackDevelopment,
    /// TLS is terminated by the server or a configured trusted ingress.
    Protected,
}

/// Validated process configuration containing no secret values.
pub struct RuntimeConfig {
    listen_address: SocketAddr,
    data_directory: PathBuf,
    transport_mode: TransportMode,
    request_body_limit: usize,
    shutdown_grace: Duration,
}

impl RuntimeConfig {
    /// Builds safe local development defaults around an explicit data path.
    #[must_use]
    pub fn development(data_directory: PathBuf) -> Self {
        Self {
            listen_address: SocketAddr::from(([127, 0, 0, 1], 8080)),
            data_directory,
            transport_mode: TransportMode::LoopbackDevelopment,
            request_body_limit: 1024 * 1024,
            shutdown_grace: Duration::from_secs(15),
        }
    }

    /// Validates security and resource invariants before adapters start.
    ///
    /// # Errors
    ///
    /// Returns an error for a relative data path, unprotected non-loopback
    /// listener, or unsupported resource bound.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.data_directory.is_absolute() {
            return Err(ConfigError::RelativeDataDirectory);
        }
        if self.transport_mode == TransportMode::LoopbackDevelopment
            && !self.listen_address.ip().is_loopback()
        {
            return Err(ConfigError::UnprotectedNetworkListener);
        }
        if !(1024..=16 * 1024 * 1024).contains(&self.request_body_limit) {
            return Err(ConfigError::RequestBodyLimit);
        }
        if !(Duration::from_secs(1)..=Duration::from_secs(120)).contains(&self.shutdown_grace) {
            return Err(ConfigError::ShutdownGrace);
        }
        Ok(())
    }

    /// Returns the configured listener.
    #[must_use]
    pub const fn listen_address(&self) -> SocketAddr {
        self.listen_address
    }

    /// Returns a redacted summary suitable for startup diagnostics.
    #[must_use]
    pub fn safe_summary(&self) -> String {
        format!(
            "listen_address={}; transport_mode={:?}; data_directory=[REDACTED]; request_body_limit={}",
            self.listen_address, self.transport_mode, self.request_body_limit
        )
    }
}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.safe_summary())
    }
}

/// Safe configuration validation failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConfigError {
    /// Persistent data must resolve below an explicit absolute directory.
    #[error("data directory must be an absolute path")]
    RelativeDataDirectory,
    /// Plaintext development transport is local-only.
    #[error("unprotected HTTP may bind only to a loopback address")]
    UnprotectedNetworkListener,
    /// Request bodies must remain within the supported hard bounds.
    #[error("request body limit is outside supported bounds")]
    RequestBodyLimit,
    /// Graceful shutdown cannot be disabled or wait indefinitely.
    #[error("shutdown grace is outside supported bounds")]
    ShutdownGrace,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ConfigError, RuntimeConfig};

    #[test]
    fn development_defaults_are_local_and_redacted() {
        let config = RuntimeConfig::development(PathBuf::from("/synthetic/smcv-data"));
        assert_eq!(config.validate(), Ok(()));
        assert!(config.listen_address().ip().is_loopback());
        assert!(!format!("{config:?}").contains("/synthetic/smcv-data"));
    }

    #[test]
    fn relative_data_path_fails_validation() {
        let config = RuntimeConfig::development(PathBuf::from("runtime"));
        assert_eq!(config.validate(), Err(ConfigError::RelativeDataDirectory));
    }
}

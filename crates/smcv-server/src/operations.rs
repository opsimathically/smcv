//! Production configuration and startup preflight.

use std::{
    collections::BTreeSet,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use axum::{
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::ApiState;

const KNOWN_ENVIRONMENT: &[&str] = &[
    "SMCV_DATA_DIR",
    "SMCV_ENVIRONMENT",
    "SMCV_KEY_DIR",
    "SMCV_LISTEN_ADDR",
    "SMCV_LOG_FORMAT",
    "SMCV_METRICS_ADDR",
    "SMCV_ORIGIN",
    "SMCV_PROTECTED_TRANSPORT",
    "SMCV_RP_ID",
    "SMCV_SHUTDOWN_GRACE_SECONDS",
    "SMCV_TRUSTED_PROXY",
];

/// Deployment posture selected before any listener opens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Environment {
    /// Local-only developer process that may initialize an empty vault.
    Development,
    /// Supervised process with existing custody and protected ingress.
    Production,
}

/// Log encoding with a closed, low-cardinality field vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogFormat {
    /// Human-readable local development output.
    Compact,
    /// Structured production output.
    Json,
}

/// Complete non-secret server configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerRuntimeConfig {
    /// Deployment posture.
    pub environment: Environment,
    /// Product listener.
    pub listen_address: SocketAddr,
    /// Local-only metrics listener when enabled.
    pub metrics_address: Option<SocketAddr>,
    /// Directory containing the `SQLite` database.
    pub data_directory: PathBuf,
    /// Separate directory containing root-provider material.
    pub key_directory: PathBuf,
    /// `WebAuthn` relying-party ID.
    pub rp_id: String,
    /// Exact browser origin.
    pub origin: String,
    /// Whether an ingress or server-side TLS protects product traffic.
    pub protected_transport: bool,
    /// Bounded shutdown drain interval.
    pub shutdown_grace: Duration,
    /// Safe log encoding.
    pub log_format: LogFormat,
}

impl ServerRuntimeConfig {
    /// Parses the closed `SMCV_*` environment schema.
    ///
    /// # Errors
    ///
    /// Returns a safe error for unknown keys, malformed values, or an invalid
    /// security combination.
    pub fn from_environment() -> Result<Self, PreflightError> {
        reject_unknown_environment()?;
        let working_directory = env::current_dir().map_err(|_| PreflightError::Environment)?;
        let environment = match env::var("SMCV_ENVIRONMENT").as_deref() {
            Ok("production") => Environment::Production,
            Ok("development") | Err(env::VarError::NotPresent) => Environment::Development,
            _ => return Err(PreflightError::Environment),
        };
        let default_data = working_directory.join(".smcv-data");
        let default_keys = working_directory.join(".smcv-key");
        let listen_address = env::var("SMCV_LISTEN_ADDR")
            .unwrap_or_else(|_| String::from("127.0.0.1:8080"))
            .parse()
            .map_err(|_| PreflightError::Environment)?;
        let metrics_address = env::var("SMCV_METRICS_ADDR")
            .ok()
            .map(|value| value.parse().map_err(|_| PreflightError::Environment))
            .transpose()?;
        let shutdown_seconds = env::var("SMCV_SHUTDOWN_GRACE_SECONDS")
            .unwrap_or_else(|_| String::from("15"))
            .parse::<u64>()
            .map_err(|_| PreflightError::Environment)?;
        let log_format = match env::var("SMCV_LOG_FORMAT").as_deref() {
            Ok("json") => LogFormat::Json,
            Ok("compact") | Err(env::VarError::NotPresent) => LogFormat::Compact,
            _ => return Err(PreflightError::Environment),
        };
        let config = Self {
            environment,
            listen_address,
            metrics_address,
            data_directory: env::var_os("SMCV_DATA_DIR").map_or(default_data, PathBuf::from),
            key_directory: env::var_os("SMCV_KEY_DIR").map_or(default_keys, PathBuf::from),
            rp_id: env::var("SMCV_RP_ID").unwrap_or_else(|_| String::from("localhost")),
            origin: env::var("SMCV_ORIGIN")
                .unwrap_or_else(|_| format!("http://localhost:{}", listen_address.port())),
            protected_transport: env::var("SMCV_PROTECTED_TRANSPORT").as_deref() == Ok("1"),
            shutdown_grace: Duration::from_secs(shutdown_seconds),
            log_format,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates configuration without opening or creating a vault.
    ///
    /// # Errors
    ///
    /// Returns a safe error if transport, origin, filesystem, proxy, or
    /// resource-bound invariants fail.
    pub fn validate(&self) -> Result<(), PreflightError> {
        if !self.data_directory.is_absolute() || !self.key_directory.is_absolute() {
            return Err(PreflightError::AbsolutePaths);
        }
        if self.data_directory == self.key_directory
            || self.data_directory.starts_with(&self.key_directory)
            || self.key_directory.starts_with(&self.data_directory)
        {
            return Err(PreflightError::SeparateCustody);
        }
        if !(Duration::from_secs(1)..=Duration::from_secs(120)).contains(&self.shutdown_grace) {
            return Err(PreflightError::ResourceBound);
        }
        if self
            .metrics_address
            .is_some_and(|address| !address.ip().is_loopback())
        {
            return Err(PreflightError::MetricsExposure);
        }
        if env::var_os("SMCV_TRUSTED_PROXY").is_some_and(|value| !value.is_empty()) {
            return Err(PreflightError::ProxyTrust);
        }
        if self.rp_id.is_empty()
            || self.rp_id.len() > 253
            || self.rp_id.contains(['/', ':', '@'])
            || self.origin.contains(['\n', '\r', '@', '?', '#'])
        {
            return Err(PreflightError::Origin);
        }
        if self.environment == Environment::Production {
            if !self.listen_address.ip().is_loopback()
                || !self.protected_transport
                || !self.origin.starts_with("https://")
            {
                return Err(PreflightError::Transport);
            }
            if self.log_format != LogFormat::Json {
                return Err(PreflightError::LogFormat);
            }
            validate_existing_directory(&self.data_directory)?;
            validate_existing_directory(&self.key_directory)?;
            validate_existing_file(&self.database_path())?;
            validate_existing_file(&self.root_key_path())?;
        } else if !self.listen_address.ip().is_loopback() && !self.protected_transport {
            return Err(PreflightError::Transport);
        }
        Ok(())
    }

    /// Opens and cryptographically verifies the configured existing vault.
    ///
    /// Development mode may initialize an absent vault. Production requires
    /// existing paths before this method is reached.
    ///
    /// # Errors
    ///
    /// Returns a safe error for custody, schema, database, or integrity
    /// failures.
    pub fn open_state(&self) -> Result<ApiState, PreflightError> {
        self.validate()?;
        let state = ApiState::open(
            &self.database_path(),
            &self.root_key_path(),
            &self.rp_id,
            &self.origin,
        )
        .map_err(|_| PreflightError::Vault)?;
        if !state.vault().store.quick_integrity_check().unwrap_or(false) {
            return Err(PreflightError::Vault);
        }
        Ok(state)
    }

    /// `SQLite` path derived from the protected data directory.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.data_directory.join("vault.sqlite")
    }

    /// Root-provider path derived from the separate key directory.
    #[must_use]
    pub fn root_key_path(&self) -> PathBuf {
        self.key_directory.join("root.key")
    }

    /// Redacted summary suitable for structured startup logs.
    #[must_use]
    pub fn safe_summary(&self) -> String {
        format!(
            "environment={:?}; listen_address={}; metrics_address={}; origin_scheme={}; protected_transport={}; shutdown_grace_seconds={}; data_directory=[REDACTED]; key_directory=[REDACTED]",
            self.environment,
            self.listen_address,
            self.metrics_address
                .map_or_else(|| "disabled".to_owned(), |value| value.to_string()),
            if self.origin.starts_with("https://") {
                "https"
            } else {
                "http"
            },
            self.protected_transport,
            self.shutdown_grace.as_secs(),
        )
    }
}

/// Safe startup/preflight failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PreflightError {
    /// An environment key or value is not in the closed schema.
    #[error("server environment configuration is invalid")]
    Environment,
    /// Persistent paths must be explicit and absolute.
    #[error("data and key directories must be absolute")]
    AbsolutePaths,
    /// Root-provider and database custody must use different directories.
    #[error("data and root-provider directories must be separate")]
    SeparateCustody,
    /// Product traffic is not configured for an allowed transport.
    #[error("production transport configuration is invalid")]
    Transport,
    /// `WebAuthn` relying-party or browser-origin input is invalid.
    #[error("browser origin or relying-party configuration is invalid")]
    Origin,
    /// Production structured logging was not selected.
    #[error("production requires structured JSON logging")]
    LogFormat,
    /// Trusted forwarding headers are unsupported and therefore rejected.
    #[error("trusted-proxy header mode is not supported; clear forwarding headers at ingress")]
    ProxyTrust,
    /// Metrics may bind only to loopback.
    #[error("metrics listener must bind to loopback")]
    MetricsExposure,
    /// A configured timeout or other work bound is unsupported.
    #[error("server resource bound is outside the supported range")]
    ResourceBound,
    /// Existing production custody has an unsafe type or permission mode.
    #[error("production path is missing or has unsafe permissions")]
    UnsafePath,
    /// The existing vault, root provider, schema, or integrity check failed.
    #[error("configured vault failed startup verification")]
    Vault,
}

fn reject_unknown_environment() -> Result<(), PreflightError> {
    let known: BTreeSet<&str> = KNOWN_ENVIRONMENT.iter().copied().collect();
    if env::vars_os().any(|(key, _)| {
        key.to_str()
            .is_some_and(|key| key.starts_with("SMCV_") && !known.contains(key))
    }) {
        return Err(PreflightError::Environment);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_existing_directory(path: &Path) -> Result<(), PreflightError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| PreflightError::UnsafePath)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != current_effective_uid()?
    {
        return Err(PreflightError::UnsafePath);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_existing_file(path: &Path) -> Result<(), PreflightError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| PreflightError::UnsafePath)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != current_effective_uid()?
    {
        return Err(PreflightError::UnsafePath);
    }
    Ok(())
}

#[cfg(unix)]
fn current_effective_uid() -> Result<u32, PreflightError> {
    let status =
        std::fs::read_to_string("/proc/self/status").map_err(|_| PreflightError::UnsafePath)?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|values| values.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or(PreflightError::UnsafePath)
}

#[cfg(not(unix))]
fn validate_existing_directory(_path: &Path) -> Result<(), PreflightError> {
    Err(PreflightError::UnsafePath)
}

#[cfg(not(unix))]
fn validate_existing_file(_path: &Path) -> Result<(), PreflightError> {
    Err(PreflightError::UnsafePath)
}

pub(crate) async fn metrics(State(state): State<ApiState>) -> Response {
    let ready = state.vault().store.quick_integrity_check().unwrap_or(false);
    let metrics = &state.metrics;
    let body = format!(
        concat!(
            "# HELP smcv_process_ready Whether local vault readiness currently passes.\n",
            "# TYPE smcv_process_ready gauge\n",
            "smcv_process_ready {}\n",
            "# TYPE smcv_http_requests_total counter\n",
            "smcv_http_requests_total {}\n",
            "# TYPE smcv_http_responses_total counter\n",
            "smcv_http_responses_total{{class=\"success\"}} {}\n",
            "smcv_http_responses_total{{class=\"client_error\"}} {}\n",
            "smcv_http_responses_total{{class=\"server_error\"}} {}\n",
            "# TYPE smcv_request_timeouts_total counter\n",
            "smcv_request_timeouts_total {}\n",
            "# TYPE smcv_rate_limited_total counter\n",
            "smcv_rate_limited_total {}\n",
            "# TYPE smcv_readiness_checks_total counter\n",
            "smcv_readiness_checks_total {}\n",
            "# TYPE smcv_readiness_failures_total counter\n",
            "smcv_readiness_failures_total {}\n",
        ),
        u8::from(ready),
        metrics.requests.load(std::sync::atomic::Ordering::Relaxed),
        metrics
            .responses_success
            .load(std::sync::atomic::Ordering::Relaxed),
        metrics
            .responses_client_error
            .load(std::sync::atomic::Ordering::Relaxed),
        metrics
            .responses_server_error
            .load(std::sync::atomic::Ordering::Relaxed),
        metrics.timeouts.load(std::sync::atomic::Ordering::Relaxed),
        metrics
            .rate_limited
            .load(std::sync::atomic::Ordering::Relaxed),
        metrics
            .readiness_checks
            .load(std::sync::atomic::Ordering::Relaxed),
        metrics
            .readiness_failures
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::{fs, net::SocketAddr, time::Duration};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::{Environment, LogFormat, PreflightError, ServerRuntimeConfig};

    fn production(root: &TempDir) -> ServerRuntimeConfig {
        ServerRuntimeConfig {
            environment: Environment::Production,
            listen_address: SocketAddr::from(([127, 0, 0, 1], 8080)),
            metrics_address: Some(SocketAddr::from(([127, 0, 0, 1], 9090))),
            data_directory: root.path().join("data"),
            key_directory: root.path().join("keys"),
            rp_id: String::from("vault.example.test"),
            origin: String::from("https://vault.example.test"),
            protected_transport: true,
            shutdown_grace: Duration::from_secs(15),
            log_format: LogFormat::Json,
        }
    }

    #[test]
    fn production_rejects_missing_and_unsafe_custody_before_open() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let config = production(&root);
        assert_eq!(config.validate(), Err(PreflightError::UnsafePath));

        fs::create_dir(&config.data_directory)
            .unwrap_or_else(|error| panic!("data directory: {error}"));
        fs::create_dir(&config.key_directory)
            .unwrap_or_else(|error| panic!("key directory: {error}"));
        fs::set_permissions(&config.data_directory, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("data mode: {error}"));
        fs::set_permissions(&config.key_directory, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("key mode: {error}"));
        fs::write(config.database_path(), b"synthetic")
            .unwrap_or_else(|error| panic!("database fixture: {error}"));
        fs::write(config.root_key_path(), b"synthetic")
            .unwrap_or_else(|error| panic!("root fixture: {error}"));
        fs::set_permissions(config.database_path(), fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("database mode: {error}"));
        fs::set_permissions(config.root_key_path(), fs::Permissions::from_mode(0o644))
            .unwrap_or_else(|error| panic!("root mode: {error}"));
        assert_eq!(config.validate(), Err(PreflightError::UnsafePath));
    }

    #[test]
    fn production_rejects_plaintext_external_metrics_and_ambiguous_origin() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let mut config = production(&root);
        config.protected_transport = false;
        assert_eq!(config.validate(), Err(PreflightError::Transport));

        config.protected_transport = true;
        config.listen_address = SocketAddr::from(([0, 0, 0, 0], 8080));
        assert_eq!(config.validate(), Err(PreflightError::Transport));

        config.listen_address = SocketAddr::from(([127, 0, 0, 1], 8080));
        config.metrics_address = Some(SocketAddr::from(([0, 0, 0, 0], 9090)));
        assert_eq!(config.validate(), Err(PreflightError::MetricsExposure));

        config.metrics_address = None;
        config.origin = String::from("https://owner@vault.example.test");
        assert_eq!(config.validate(), Err(PreflightError::Origin));
    }
}

use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use smcv_core::{AuthenticatorId, ObjectId, PrincipalId, ProtectedString, RequestId, SessionId};
use smcv_crypto::{
    SessionVerifier, issue_session, session_lookup_id, state_commitment, verify_csrf,
    verify_session,
};
use smcv_storage::{
    AuthenticatorKind, OwnerAuthenticatorInsert, OwnerAuthenticatorRecord, PrincipalRecord,
    SessionInsert, SessionRecord, StorageError,
};
use thiserror::Error;

use crate::{InitializedVault, VaultOperationContext};

const SESSION_IDLE_MS: i64 = 30 * 60 * 1_000;
const SESSION_ABSOLUTE_MS: i64 = 12 * 60 * 60 * 1_000;
const RECENT_AUTH_MS: i64 = 5 * 60 * 1_000;
const MIN_PASSWORD_BYTES: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1_024;

/// One-use process-local authority for the initial owner enrollment path.
///
/// Only the local CLI adapter can construct this value; the HTTP adapter has
/// no route that can remotely claim an empty installation.
pub struct LocalSetupCapability {
    _private: (),
}

impl LocalSetupCapability {
    /// Constructs initial-enrollment authority for the local CLI adapter.
    #[must_use]
    pub const fn for_local_cli() -> Self {
        Self { _private: () }
    }
}

/// Display-once browser session secrets returned after authentication.
pub struct BrowserSessionSecrets {
    /// Opaque session cookie value. It is never persisted in cleartext.
    pub session_token: ProtectedString,
    /// Opaque CSRF value for a same-origin response body/header.
    pub csrf_token: ProtectedString,
    /// Absolute expiration used to bound browser cookie lifetime.
    pub absolute_expires_at_unix_ms: i64,
}

impl core::fmt::Debug for BrowserSessionSecrets {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BrowserSessionSecrets")
            .field("session_token", &"[REDACTED]")
            .field("csrf_token", &"[REDACTED]")
            .field(
                "absolute_expires_at_unix_ms",
                &self.absolute_expires_at_unix_ms,
            )
            .finish()
    }
}

/// Verified browser identity context for centralized authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedOwner {
    /// Stable owner principal.
    principal_id: PrincipalId,
    /// Server-side session reference for audit attribution and revocation.
    session_id: SessionId,
    /// Authenticator that established this session.
    authenticator_id: AuthenticatorId,
    /// Whether the configured recent-authentication window is still valid.
    recent_auth_until_unix_ms: i64,
    valid_until_unix_ms: i64,
}

impl AuthenticatedOwner {
    /// Returns the authenticated owner principal.
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    /// Returns the server-side session reference.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the authenticator that established the session.
    #[must_use]
    pub const fn authenticator_id(&self) -> AuthenticatorId {
        self.authenticator_id
    }

    /// Reports whether the recent-authentication window remains valid.
    #[must_use]
    pub const fn is_recent_at(&self, now_unix_ms: i64) -> bool {
        now_unix_ms <= self.recent_auth_until_unix_ms && self.is_valid_at(now_unix_ms)
    }

    /// Reports whether this request authentication result remains in its
    /// bounded server-side session window.
    #[must_use]
    pub const fn is_valid_at(&self, now_unix_ms: i64) -> bool {
        now_unix_ms <= self.valid_until_unix_ms
    }
}

/// Safe owner-authentication failures with a uniform external category.
#[derive(Debug, Error)]
pub enum AuthenticationError {
    /// Authentication failed without exposing account, session, or verifier state.
    #[error("authentication failed")]
    Rejected,
    /// Initial enrollment input violates a documented bound.
    #[error("authentication input is invalid")]
    InvalidInput,
    /// Protected authentication state does not authenticate.
    #[error("authentication state integrity check failed")]
    Integrity,
    /// Authentication persistence could not complete safely.
    #[error("authentication service is unavailable")]
    Unavailable,
}

impl InitializedVault {
    /// Enrolls the sole owner through the local-only first-claim path.
    ///
    /// # Errors
    ///
    /// Returns a safe error for invalid password bounds, repeated enrollment,
    /// hashing failure, integrity failure, or unavailable persistence.
    pub fn enroll_local_owner(
        &self,
        _capability: LocalSetupCapability,
        password: &ProtectedString,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<PrincipalId, AuthenticationError> {
        validate_password(password)?;
        let password_phc = hash_password(password)?;
        let principal_id = PrincipalId::random();
        let authenticator_id = AuthenticatorId::random();
        let principal_commitment = principal_commitment(self, principal_id, "owner", "active", 1)?;
        let authenticator_commitment = authenticator_commitment(
            self,
            authenticator_id,
            principal_id,
            AuthenticatorKind::Password,
            None,
            None,
            Some(&password_phc),
            "active",
            now_unix_ms,
            None,
            None,
        )?;
        let authenticator = OwnerAuthenticatorInsert {
            authenticator_id,
            kind: AuthenticatorKind::Password,
            credential_lookup: None,
            credential_data: None,
            password_phc: Some(&password_phc),
            state_commitment: authenticator_commitment,
        };
        let authorization_commitment = state_commitment(
            self.audit_key(),
            b"authorization-graph\0v1\0revision\0\x31\0empty",
        )
        .map(|value| *value.as_bytes())
        .map_err(|_| AuthenticationError::Integrity)?;
        let operation = VaultOperationContext {
            request_id,
            actor_principal_id: None,
            credential_kind: None,
            credential_id: None,
            now_unix_ms,
        };
        let audit = self
            .build_audit(
                "owner:enroll",
                "principal",
                Some(ObjectId::from_uuid(principal_id.as_uuid())),
                operation,
            )
            .map_err(|_| AuthenticationError::Unavailable)?;
        self.store
            .enroll_owner(
                principal_id,
                &principal_commitment,
                &authorization_commitment,
                &authenticator,
                now_unix_ms,
                &audit,
            )
            .map_err(map_storage)?;
        Ok(principal_id)
    }

    /// Verifies the owner password and creates a rotated server-side session.
    ///
    /// # Errors
    ///
    /// Returns the same rejected category for an unknown owner, wrong password,
    /// revoked authenticator, or malformed credential state.
    pub fn login_with_password(
        &self,
        password: &ProtectedString,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<BrowserSessionSecrets, AuthenticationError> {
        if password.expose().len() > MAX_PASSWORD_BYTES {
            return Err(AuthenticationError::Rejected);
        }
        let owner = self
            .store
            .owner_principal()
            .map_err(map_storage)?
            .ok_or(AuthenticationError::Rejected)?;
        verify_principal_commitment(self, &owner)?;
        if owner.state != "active" {
            return Err(AuthenticationError::Rejected);
        }
        let authenticators = self
            .store
            .owner_authenticators(AuthenticatorKind::Password)
            .map_err(map_storage)?;
        let mut matched = None;
        for candidate in authenticators {
            if verify_password_record(self, &candidate, password)? {
                matched = Some(candidate);
                break;
            }
        }
        let authenticator = matched.ok_or(AuthenticationError::Rejected)?;
        self.create_browser_session(&owner, &authenticator, None, request_id, now_unix_ms)
    }

    /// Authenticates and advances a browser session, optionally requiring CSRF.
    ///
    /// # Errors
    ///
    /// Returns a uniform rejection for malformed, expired, revoked, raced, or
    /// mismatched session/CSRF tokens and integrity for committed-state changes.
    pub fn authenticate_browser_session(
        &self,
        session_token: &ProtectedString,
        csrf_token: Option<&ProtectedString>,
        require_csrf: bool,
        now_unix_ms: i64,
    ) -> Result<AuthenticatedOwner, AuthenticationError> {
        let lookup =
            session_lookup_id(session_token.expose()).ok_or(AuthenticationError::Rejected)?;
        let session = self
            .store
            .session_by_lookup(&lookup)
            .map_err(map_storage)?
            .ok_or(AuthenticationError::Rejected)?;
        verify_session_commitment(self, &session)?;
        if session.revoked_at_unix_ms.is_some()
            || session.idle_expires_at_unix_ms < now_unix_ms
            || session.absolute_expires_at_unix_ms < now_unix_ms
            || !verify_session(
                self.token_verifier_key(),
                session_token.expose(),
                &lookup,
                &SessionVerifier::from_bytes(session.verifier),
            )
            .map_err(|_| AuthenticationError::Unavailable)?
        {
            return Err(AuthenticationError::Rejected);
        }
        if require_csrf {
            let csrf = csrf_token.ok_or(AuthenticationError::Rejected)?;
            if !verify_csrf(
                self.token_verifier_key(),
                csrf.expose(),
                &lookup,
                &SessionVerifier::from_bytes(session.csrf_verifier),
            )
            .map_err(|_| AuthenticationError::Unavailable)?
            {
                return Err(AuthenticationError::Rejected);
            }
        }
        let owner = self
            .store
            .principal(session.principal_id)
            .map_err(map_storage)?;
        verify_principal_commitment(self, &owner)?;
        if owner.state != "active" {
            return Err(AuthenticationError::Rejected);
        }
        let next_idle = now_unix_ms
            .checked_add(SESSION_IDLE_MS)
            .ok_or(AuthenticationError::Rejected)?
            .min(session.absolute_expires_at_unix_ms);
        let next_commitment = session_commitment(
            self,
            &session,
            now_unix_ms,
            next_idle,
            session.recent_auth_at_unix_ms,
            None,
        )?;
        self.store
            .touch_session(
                session.session_id,
                session.last_used_at_unix_ms,
                now_unix_ms,
                next_idle,
                session.recent_auth_at_unix_ms,
                &next_commitment,
            )
            .map_err(|_| AuthenticationError::Rejected)?;
        Ok(AuthenticatedOwner {
            principal_id: session.principal_id,
            session_id: session.session_id,
            authenticator_id: session.authenticator_id,
            recent_auth_until_unix_ms: session
                .recent_auth_at_unix_ms
                .checked_add(RECENT_AUTH_MS)
                .ok_or(AuthenticationError::Rejected)?,
            valid_until_unix_ms: next_idle,
        })
    }

    /// Revokes an authenticated browser session and audits logout atomically.
    ///
    /// # Errors
    ///
    /// Returns rejected for an expired, stale, or already revoked session and
    /// integrity/unavailable for committed-state or persistence failures.
    pub fn logout_browser_session(
        &self,
        owner: AuthenticatedOwner,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<(), AuthenticationError> {
        let _gate = self
            .authorization_gate
            .write()
            .map_err(|_| AuthenticationError::Unavailable)?;
        if !owner.is_valid_at(now_unix_ms) {
            return Err(AuthenticationError::Rejected);
        }
        let session = self
            .store
            .session(owner.session_id())
            .map_err(map_storage)?;
        verify_session_commitment(self, &session)?;
        if session.principal_id != owner.principal_id() || session.revoked_at_unix_ms.is_some() {
            return Err(AuthenticationError::Rejected);
        }
        let commitment = session_commitment(
            self,
            &session,
            session.last_used_at_unix_ms,
            session.idle_expires_at_unix_ms,
            session.recent_auth_at_unix_ms,
            Some(now_unix_ms),
        )?;
        let audit = self
            .build_audit(
                "session:revoke",
                "session",
                Some(ObjectId::from_uuid(session.session_id.as_uuid())),
                VaultOperationContext {
                    request_id,
                    actor_principal_id: Some(owner.principal_id()),
                    credential_kind: Some("session"),
                    credential_id: Some(ObjectId::from_uuid(owner.session_id().as_uuid())),
                    now_unix_ms,
                },
            )
            .map_err(|_| AuthenticationError::Unavailable)?;
        self.store
            .revoke_session(
                session.session_id,
                session.last_used_at_unix_ms,
                now_unix_ms,
                &commitment,
                &audit,
            )
            .map_err(map_storage)
    }

    pub(crate) fn create_browser_session(
        &self,
        owner: &PrincipalRecord,
        authenticator: &OwnerAuthenticatorRecord,
        updated_credential_data: Option<Vec<u8>>,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<BrowserSessionSecrets, AuthenticationError> {
        let issued = issue_session(self.token_verifier_key())
            .map_err(|_| AuthenticationError::Unavailable)?;
        let session_id = SessionId::random();
        let idle_expires_at_unix_ms = now_unix_ms
            .checked_add(SESSION_IDLE_MS)
            .ok_or(AuthenticationError::Unavailable)?;
        let absolute_expires_at_unix_ms = now_unix_ms
            .checked_add(SESSION_ABSOLUTE_MS)
            .ok_or(AuthenticationError::Unavailable)?;
        let session = SessionRecord {
            session_id,
            lookup_id: issued.lookup_id,
            verifier: *issued.session_verifier.as_bytes(),
            csrf_verifier: *issued.csrf_verifier.as_bytes(),
            principal_id: owner.principal_id,
            authenticator_id: authenticator.authenticator_id,
            auth_method: authenticator.kind,
            created_at_unix_ms: now_unix_ms,
            last_used_at_unix_ms: now_unix_ms,
            idle_expires_at_unix_ms,
            absolute_expires_at_unix_ms,
            recent_auth_at_unix_ms: now_unix_ms,
            revoked_at_unix_ms: None,
            state_commitment: [0; 32],
        };
        let durable_session_commitment = session_commitment(
            self,
            &session,
            now_unix_ms,
            idle_expires_at_unix_ms,
            now_unix_ms,
            None,
        )?;
        let durable_authenticator_commitment = authenticator_commitment(
            self,
            authenticator.authenticator_id,
            authenticator.principal_id,
            authenticator.kind,
            authenticator.credential_lookup.as_deref(),
            updated_credential_data
                .as_deref()
                .or(authenticator.credential_data.as_deref()),
            authenticator.password_phc.as_deref(),
            &authenticator.state,
            authenticator.created_at_unix_ms,
            Some(now_unix_ms),
            authenticator.revoked_at_unix_ms,
        )?;
        let insert = SessionInsert {
            session_id,
            lookup_id: issued.lookup_id,
            verifier: *issued.session_verifier.as_bytes(),
            csrf_verifier: *issued.csrf_verifier.as_bytes(),
            principal_id: owner.principal_id,
            authenticator_id: authenticator.authenticator_id,
            auth_method: authenticator.kind,
            created_at_unix_ms: now_unix_ms,
            idle_expires_at_unix_ms,
            absolute_expires_at_unix_ms,
            recent_auth_at_unix_ms: now_unix_ms,
            state_commitment: durable_session_commitment,
            authenticator_state_commitment: durable_authenticator_commitment,
            authenticator_credential_data: updated_credential_data,
        };
        let operation = VaultOperationContext {
            request_id,
            actor_principal_id: Some(owner.principal_id),
            credential_kind: Some("session"),
            credential_id: Some(ObjectId::from_uuid(session_id.as_uuid())),
            now_unix_ms,
        };
        let audit = self
            .build_audit(
                "session:create",
                "session",
                Some(ObjectId::from_uuid(session_id.as_uuid())),
                operation,
            )
            .map_err(|_| AuthenticationError::Unavailable)?;
        self.store
            .create_session(&insert, &audit)
            .map_err(map_storage)?;
        Ok(BrowserSessionSecrets {
            session_token: issued.session_token,
            csrf_token: issued.csrf_token,
            absolute_expires_at_unix_ms,
        })
    }
}

fn validate_password(password: &ProtectedString) -> Result<(), AuthenticationError> {
    if !(MIN_PASSWORD_BYTES..=MAX_PASSWORD_BYTES).contains(&password.expose().len()) {
        return Err(AuthenticationError::InvalidInput);
    }
    Ok(())
}

fn argon2() -> Result<Argon2<'static>, AuthenticationError> {
    let params =
        Params::new(64 * 1_024, 3, 1, Some(32)).map_err(|_| AuthenticationError::Unavailable)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_password(password: &ProtectedString) -> Result<String, AuthenticationError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()?
        .hash_password(password.expose().as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AuthenticationError::Unavailable)
}

fn verify_password_record(
    vault: &InitializedVault,
    record: &OwnerAuthenticatorRecord,
    password: &ProtectedString,
) -> Result<bool, AuthenticationError> {
    verify_authenticator_commitment(vault, record)?;
    let phc = record
        .password_phc
        .as_deref()
        .ok_or(AuthenticationError::Integrity)?;
    let parsed = PasswordHash::new(phc).map_err(|_| AuthenticationError::Integrity)?;
    Ok(argon2()?
        .verify_password(password.expose().as_bytes(), &parsed)
        .is_ok())
}

pub(crate) fn principal_commitment(
    vault: &InitializedVault,
    principal_id: PrincipalId,
    kind: &str,
    state: &str,
    revision: u64,
) -> Result<[u8; 32], AuthenticationError> {
    let canonical = format!("principal\0{principal_id}\0{kind}\0{state}\0{revision}");
    state_commitment(vault.audit_key(), canonical.as_bytes())
        .map(|value| *value.as_bytes())
        .map_err(|_| AuthenticationError::Integrity)
}

pub(crate) fn verify_principal_commitment(
    vault: &InitializedVault,
    principal: &PrincipalRecord,
) -> Result<(), AuthenticationError> {
    let kind = match principal.kind {
        smcv_storage::PrincipalKind::Owner => "owner",
        smcv_storage::PrincipalKind::Service => "service",
    };
    if principal_commitment(
        vault,
        principal.principal_id,
        kind,
        &principal.state,
        principal.revision,
    )? != principal.state_commitment
    {
        return Err(AuthenticationError::Integrity);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn authenticator_commitment(
    vault: &InitializedVault,
    authenticator_id: AuthenticatorId,
    principal_id: PrincipalId,
    kind: AuthenticatorKind,
    credential_lookup: Option<&[u8]>,
    credential_data: Option<&[u8]>,
    password_phc: Option<&str>,
    state: &str,
    created_at_unix_ms: i64,
    last_used_at_unix_ms: Option<i64>,
    revoked_at_unix_ms: Option<i64>,
) -> Result<[u8; 32], AuthenticationError> {
    let canonical = format!(
        "authenticator\0{authenticator_id}\0{principal_id}\0{}\0{}\0{}\0{}\0{state}\0{created_at_unix_ms}\0{last_used_at_unix_ms:?}\0{revoked_at_unix_ms:?}",
        match kind {
            AuthenticatorKind::Password => "password",
            AuthenticatorKind::Passkey => "passkey",
            AuthenticatorKind::Recovery => "recovery",
        },
        credential_lookup.map(hex::encode).unwrap_or_default(),
        credential_data.map(hex::encode).unwrap_or_default(),
        password_phc.unwrap_or("")
    );
    state_commitment(vault.audit_key(), canonical.as_bytes())
        .map(|value| *value.as_bytes())
        .map_err(|_| AuthenticationError::Integrity)
}

pub(crate) fn verify_authenticator_commitment(
    vault: &InitializedVault,
    authenticator: &OwnerAuthenticatorRecord,
) -> Result<(), AuthenticationError> {
    if authenticator_commitment(
        vault,
        authenticator.authenticator_id,
        authenticator.principal_id,
        authenticator.kind,
        authenticator.credential_lookup.as_deref(),
        authenticator.credential_data.as_deref(),
        authenticator.password_phc.as_deref(),
        &authenticator.state,
        authenticator.created_at_unix_ms,
        authenticator.last_used_at_unix_ms,
        authenticator.revoked_at_unix_ms,
    )? != authenticator.state_commitment
    {
        return Err(AuthenticationError::Integrity);
    }
    Ok(())
}

fn session_commitment(
    vault: &InitializedVault,
    session: &SessionRecord,
    last_used_at_unix_ms: i64,
    idle_expires_at_unix_ms: i64,
    recent_auth_at_unix_ms: i64,
    revoked_at_unix_ms: Option<i64>,
) -> Result<[u8; 32], AuthenticationError> {
    let mut canonical = format!(
        "session\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{last_used_at_unix_ms}\0{idle_expires_at_unix_ms}\0{}\0{recent_auth_at_unix_ms}\0{revoked_at_unix_ms:?}",
        session.session_id,
        hex::encode(session.lookup_id),
        hex::encode(session.verifier),
        hex::encode(session.csrf_verifier),
        session.principal_id,
        session.authenticator_id,
        match session.auth_method {
            AuthenticatorKind::Password => "password",
            AuthenticatorKind::Passkey => "passkey",
            AuthenticatorKind::Recovery => "recovery",
        },
        session.created_at_unix_ms,
        session.absolute_expires_at_unix_ms,
        session.state_commitment.len(),
        session.absolute_expires_at_unix_ms,
    );
    canonical.shrink_to_fit();
    state_commitment(vault.audit_key(), canonical.as_bytes())
        .map(|value| *value.as_bytes())
        .map_err(|_| AuthenticationError::Integrity)
}

pub(crate) fn verify_session_commitment(
    vault: &InitializedVault,
    session: &SessionRecord,
) -> Result<(), AuthenticationError> {
    if session_commitment(
        vault,
        session,
        session.last_used_at_unix_ms,
        session.idle_expires_at_unix_ms,
        session.recent_auth_at_unix_ms,
        session.revoked_at_unix_ms,
    )? != session.state_commitment
    {
        return Err(AuthenticationError::Integrity);
    }
    Ok(())
}

pub(crate) fn verify_owner_context_active(
    vault: &InitializedVault,
    owner: AuthenticatedOwner,
    now_unix_ms: i64,
) -> Result<(), AuthenticationError> {
    if !owner.is_valid_at(now_unix_ms) {
        return Err(AuthenticationError::Rejected);
    }
    let session = vault
        .store
        .session(owner.session_id())
        .map_err(map_storage)?;
    verify_session_commitment(vault, &session)?;
    if session.principal_id != owner.principal_id()
        || session.revoked_at_unix_ms.is_some()
        || session.idle_expires_at_unix_ms < now_unix_ms
        || session.absolute_expires_at_unix_ms < now_unix_ms
    {
        return Err(AuthenticationError::Rejected);
    }
    Ok(())
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "this function is passed directly to Result::map_err"
)]
pub(crate) fn map_storage(error: StorageError) -> AuthenticationError {
    match error {
        StorageError::InvalidData | StorageError::MigrationMismatch => {
            AuthenticationError::Integrity
        }
        StorageError::Conflict | StorageError::StateConflict => AuthenticationError::Rejected,
        _ => AuthenticationError::Unavailable,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use smcv_core::{ProtectedString, RequestId};
    use tempfile::TempDir;

    use crate::{LocalSetupCapability, RequestPrincipal, initialize_vault};

    fn fixture() -> (TempDir, crate::InitializedVault) {
        let root = TempDir::new()
            .unwrap_or_else(|error| panic!("synthetic directory must create: {error}"));
        let database_directory = root.path().join("database");
        let key_directory = root.path().join("key");
        fs::create_dir_all(&database_directory)
            .unwrap_or_else(|error| panic!("database directory must create: {error}"));
        fs::create_dir_all(&key_directory)
            .unwrap_or_else(|error| panic!("key directory must create: {error}"));
        fs::set_permissions(&database_directory, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("database directory must restrict: {error}"));
        fs::set_permissions(&key_directory, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("key directory must restrict: {error}"));
        let vault = initialize_vault(
            &database_directory.join("vault.sqlite"),
            &key_directory.join("root.key"),
            1_800_000_000_000,
        )
        .unwrap_or_else(|error| panic!("synthetic vault must initialize: {error}"));
        (root, vault)
    }

    #[test]
    fn local_enrollment_password_login_session_and_csrf_round_trip() {
        let (_root, vault) = fixture();
        let password = ProtectedString::new(String::from("synthetic long password"));
        let principal = vault
            .enroll_local_owner(
                LocalSetupCapability::for_local_cli(),
                &password,
                RequestId::random(),
                1_800_000_001_000,
            )
            .unwrap_or_else(|error| panic!("synthetic owner must enroll: {error}"));
        let issued = vault
            .login_with_password(&password, RequestId::random(), 1_800_000_002_000)
            .unwrap_or_else(|error| panic!("synthetic owner must login: {error}"));
        let authenticated = vault
            .authenticate_browser_session(
                &issued.session_token,
                Some(&issued.csrf_token),
                true,
                1_800_000_003_000,
            )
            .unwrap_or_else(|error| panic!("synthetic session must authenticate: {error}"));

        assert_eq!(authenticated.principal_id(), principal);
        assert!(authenticated.is_recent_at(1_800_000_003_000));
        assert!(!format!("{issued:?}").contains("synthetic long password"));
        assert!(
            vault
                .authenticate_browser_session(
                    &issued.session_token,
                    Some(&ProtectedString::new(String::from("smcvc_v1.invalid"))),
                    true,
                    1_800_000_004_000,
                )
                .is_err()
        );

        let stale_recent = vault
            .authenticate_browser_session(&issued.session_token, None, false, 1_800_000_303_001)
            .unwrap_or_else(|error| panic!("valid non-recent session must authenticate: {error}"));
        assert!(!stale_recent.is_recent_at(1_800_000_303_001));
        let guarded = vault
            .authorized(
                RequestPrincipal::Owner(stale_recent),
                RequestId::random(),
                1_800_000_303_001,
            )
            .unwrap_or_else(|error| {
                panic!("non-recent request may reach low-risk boundary: {error}")
            });
        assert!(guarded.secrets_due(10).is_err());
        drop(guarded);

        vault
            .logout_browser_session(stale_recent, RequestId::random(), 1_800_000_304_000)
            .unwrap_or_else(|error| panic!("active session must logout: {error}"));
        assert!(
            vault
                .authenticate_browser_session(
                    &issued.session_token,
                    None,
                    false,
                    1_800_000_304_001,
                )
                .is_err()
        );
        assert!(
            vault
                .authorized(
                    RequestPrincipal::Owner(stale_recent),
                    RequestId::random(),
                    1_800_000_304_001,
                )
                .is_err()
        );
    }

    #[test]
    fn initial_owner_enrollment_cannot_be_replayed() {
        let (_root, vault) = fixture();
        let password = ProtectedString::new(String::from("synthetic long password"));
        vault
            .enroll_local_owner(
                LocalSetupCapability::for_local_cli(),
                &password,
                RequestId::random(),
                1_800_000_001_000,
            )
            .unwrap_or_else(|error| panic!("synthetic owner must enroll: {error}"));
        assert!(
            vault
                .enroll_local_owner(
                    LocalSetupCapability::for_local_cli(),
                    &password,
                    RequestId::random(),
                    1_800_000_002_000,
                )
                .is_err()
        );
    }
}

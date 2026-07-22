use rusqlite::{OptionalExtension, params};
use smcv_core::{AuthenticatorId, CredentialId, PrincipalId, SessionId};
use uuid::Uuid;

use crate::{
    AuditRecord, EncryptedRecord, SqliteStore, StorageError, StorageResult,
    records::{insert_audit, require_audit_head},
};

/// Principal category with distinct authentication and authorization behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    Owner,
    Service,
}

impl PrincipalKind {
    fn parse(value: &str) -> StorageResult<Self> {
        match value {
            "owner" => Ok(Self::Owner),
            "service" => Ok(Self::Service),
            _ => Err(StorageError::InvalidData),
        }
    }
}

/// Owner authenticator kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorKind {
    Password,
    Passkey,
    Recovery,
}

impl AuthenticatorKind {
    fn parse(value: &str) -> StorageResult<Self> {
        match value {
            "password" => Ok(Self::Password),
            "passkey" => Ok(Self::Passkey),
            "recovery" => Ok(Self::Recovery),
            _ => Err(StorageError::InvalidData),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Passkey => "passkey",
            Self::Recovery => "recovery",
        }
    }
}

/// Authenticated clear principal state plus its keyed commitment.
pub struct PrincipalRecord {
    pub principal_id: PrincipalId,
    pub kind: PrincipalKind,
    pub state: String,
    pub revision: u64,
    pub state_commitment: [u8; 32],
}

/// New owner authenticator persisted without raw secret material.
pub struct OwnerAuthenticatorInsert<'a> {
    pub authenticator_id: AuthenticatorId,
    pub kind: AuthenticatorKind,
    pub credential_lookup: Option<&'a [u8]>,
    pub credential_data: Option<&'a [u8]>,
    pub password_phc: Option<&'a str>,
    pub state_commitment: [u8; 32],
}

/// Stored owner authenticator material and authenticated state.
pub struct OwnerAuthenticatorRecord {
    pub authenticator_id: AuthenticatorId,
    pub principal_id: PrincipalId,
    pub kind: AuthenticatorKind,
    pub credential_lookup: Option<Vec<u8>>,
    pub credential_data: Option<Vec<u8>>,
    pub password_phc: Option<String>,
    pub state: String,
    pub created_at_unix_ms: i64,
    pub last_used_at_unix_ms: Option<i64>,
    pub revoked_at_unix_ms: Option<i64>,
    pub state_commitment: [u8; 32],
}

/// New server-side browser session containing verifier-only token material.
pub struct SessionInsert {
    pub session_id: SessionId,
    pub lookup_id: [u8; 16],
    pub verifier: [u8; 32],
    pub csrf_verifier: [u8; 32],
    pub principal_id: PrincipalId,
    pub authenticator_id: AuthenticatorId,
    pub auth_method: AuthenticatorKind,
    pub created_at_unix_ms: i64,
    pub idle_expires_at_unix_ms: i64,
    pub absolute_expires_at_unix_ms: i64,
    pub recent_auth_at_unix_ms: i64,
    pub state_commitment: [u8; 32],
    pub authenticator_state_commitment: [u8; 32],
    /// Updated passkey state after assertion verification, when applicable.
    pub authenticator_credential_data: Option<Vec<u8>>,
}

/// Stored session verifier and lifecycle state.
pub struct SessionRecord {
    pub session_id: SessionId,
    pub lookup_id: [u8; 16],
    pub verifier: [u8; 32],
    pub csrf_verifier: [u8; 32],
    pub principal_id: PrincipalId,
    pub authenticator_id: AuthenticatorId,
    pub auth_method: AuthenticatorKind,
    pub created_at_unix_ms: i64,
    pub last_used_at_unix_ms: i64,
    pub idle_expires_at_unix_ms: i64,
    pub absolute_expires_at_unix_ms: i64,
    pub recent_auth_at_unix_ms: i64,
    pub revoked_at_unix_ms: Option<i64>,
    pub state_commitment: [u8; 32],
}

/// New verifier-only application credential.
pub struct ApplicationCredentialInsert {
    pub credential_id: CredentialId,
    pub principal_id: PrincipalId,
    pub lookup_id: [u8; 12],
    pub verifier: [u8; 32],
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
    pub state_commitment: [u8; 32],
}

/// Stored verifier-only application credential state.
pub struct ApplicationCredentialRecord {
    pub credential_id: CredentialId,
    pub principal_id: PrincipalId,
    pub lookup_id: [u8; 12],
    pub verifier: [u8; 32],
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
    pub last_used_at_unix_ms: Option<i64>,
    pub revoked_at_unix_ms: Option<i64>,
    pub revision: u64,
    pub state_commitment: [u8; 32],
}

/// New encrypted service-identity record.
pub struct ServiceIdentityInsert {
    pub principal_id: PrincipalId,
    pub principal_state_commitment: [u8; 32],
    pub metadata: EncryptedRecord,
    pub created_at_unix_ms: i64,
}

/// Stored service identity with protected display metadata.
pub struct ServiceIdentityRecord {
    pub principal: PrincipalRecord,
    pub metadata_version: u64,
    pub metadata: EncryptedRecord,
}

#[allow(
    clippy::missing_errors_doc,
    reason = "each storage operation returns the shared redacted StorageError contract"
)]
impl SqliteStore {
    /// Atomically creates a service principal, protected metadata, and audit.
    pub fn create_service_identity(
        &self,
        identity: &ServiceIdentityInsert,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<()> {
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        transaction.execute(
            "INSERT INTO smcv_principals VALUES (?1, 'service', 'active', 1, ?2, ?3, ?3)",
            params![
                identity.principal_id.as_bytes(),
                identity.principal_state_commitment.as_slice(),
                identity.created_at_unix_ms,
            ],
        )?;
        transaction.execute(
            r"INSERT INTO smcv_service_identities VALUES
               (?1, 1, ?2, ?3, ?4, ?5, ?6)",
            params![
                identity.principal_id.as_bytes(),
                identity.metadata.nonce.as_slice(),
                identity.metadata.ciphertext.as_slice(),
                identity.metadata.dek_nonce.as_slice(),
                identity.metadata.wrapped_dek.as_slice(),
                i64::from(identity.metadata.kek_version),
            ],
        )?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Loads one service principal and its protected metadata envelope.
    pub fn service_identity(
        &self,
        principal_id: PrincipalId,
    ) -> StorageResult<ServiceIdentityRecord> {
        let principal = self.principal(principal_id)?;
        if principal.kind != PrincipalKind::Service {
            return Err(StorageError::InvalidData);
        }
        let connection = self.lock()?;
        let raw = connection
            .query_row(
                r"SELECT metadata_version, metadata_nonce, metadata_ciphertext,
                          metadata_dek_nonce, metadata_wrapped_dek, metadata_kek_version
                   FROM smcv_service_identities WHERE principal_id = ?1",
                [principal_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::NotInitialized)?;
        Ok(ServiceIdentityRecord {
            principal,
            metadata_version: u64::try_from(raw.0).map_err(|_| StorageError::InvalidData)?,
            metadata: EncryptedRecord {
                nonce: raw.1.try_into().map_err(|_| StorageError::InvalidData)?,
                ciphertext: raw.2,
                dek_nonce: raw.3.try_into().map_err(|_| StorageError::InvalidData)?,
                wrapped_dek: raw.4.try_into().map_err(|_| StorageError::InvalidData)?,
                kek_version: u32::try_from(raw.5).map_err(|_| StorageError::InvalidData)?,
            },
        })
    }

    /// Lists a bounded stable page of service identities by opaque ID.
    pub fn service_identities_after(
        &self,
        after_principal_id: Option<PrincipalId>,
        limit: u16,
    ) -> StorageResult<Vec<ServiceIdentityRecord>> {
        if limit == 0 {
            return Err(StorageError::InvalidData);
        }
        let after = after_principal_id.map_or([0_u8; 16], |id| *id.as_bytes());
        let ids = {
            let connection = self.lock()?;
            let mut statement = connection.prepare(
                r"SELECT s.principal_id
                     FROM smcv_service_identities AS s
                     JOIN smcv_principals AS p ON p.principal_id = s.principal_id
                    WHERE s.principal_id > ?1 AND p.principal_kind = 'service'
                    ORDER BY s.principal_id LIMIT ?2",
            )?;
            let rows = statement.query_map(params![after.as_slice(), i64::from(limit)], |row| {
                row.get::<_, Vec<u8>>(0)
            })?;
            let mut ids = Vec::with_capacity(usize::from(limit));
            for row in rows {
                ids.push(PrincipalId::from_uuid(parse_uuid(&row?)?));
            }
            ids
        };
        ids.into_iter()
            .map(|id| self.service_identity(id))
            .collect()
    }

    /// Returns the one owner principal when enrollment has completed.
    pub fn owner_principal(&self) -> StorageResult<Option<PrincipalRecord>> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT principal_id, principal_kind, state, revision, state_commitment FROM smcv_principals WHERE principal_kind = 'owner'",
                [],
                parse_principal_row,
            )
            .optional()?
            .map(parse_principal)
            .transpose()
    }

    /// Loads one principal by opaque identity.
    pub fn principal(&self, principal_id: PrincipalId) -> StorageResult<PrincipalRecord> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                "SELECT principal_id, principal_kind, state, revision, state_commitment FROM smcv_principals WHERE principal_id = ?1",
                [principal_id.as_bytes()],
                parse_principal_row,
            )
            .optional()?
            .ok_or(StorageError::NotInitialized)?;
        parse_principal(row)
    }

    /// Atomically enrolls the sole owner and initial password authenticator.
    pub fn enroll_owner(
        &self,
        principal_id: PrincipalId,
        principal_commitment: &[u8; 32],
        authorization_commitment: &[u8; 32],
        authenticator: &OwnerAuthenticatorInsert<'_>,
        now_unix_ms: i64,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<()> {
        validate_authenticator(authenticator)?;
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        if transaction.query_row(
            "SELECT count(*) FROM smcv_principals WHERE principal_kind = 'owner'",
            [],
            |row| row.get::<_, i64>(0),
        )? != 0
        {
            return Err(StorageError::Conflict);
        }
        transaction.execute(
            "INSERT INTO smcv_principals VALUES (?1, 'owner', 'active', 1, ?2, ?3, ?3)",
            params![
                principal_id.as_bytes(),
                principal_commitment.as_slice(),
                now_unix_ms
            ],
        )?;
        insert_authenticator(&transaction, principal_id, authenticator, now_unix_ms)?;
        if transaction.execute(
            "UPDATE smcv_authorization_state SET state_commitment = ?1 WHERE singleton = 1 AND revision = 1 AND state_commitment = zeroblob(32)",
            [authorization_commitment.as_slice()],
        )? != 1
        {
            return Err(StorageError::StateConflict);
        }
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Adds a passkey or recovery authenticator to the existing active owner.
    pub fn add_owner_authenticator(
        &self,
        principal_id: PrincipalId,
        authenticator: &OwnerAuthenticatorInsert<'_>,
        now_unix_ms: i64,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<()> {
        validate_authenticator(authenticator)?;
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        if transaction.query_row(
            "SELECT count(*) FROM smcv_principals WHERE principal_id = ?1 AND principal_kind = 'owner' AND state = 'active'",
            [principal_id.as_bytes()],
            |row| row.get::<_, i64>(0),
        )? != 1
        {
            return Err(StorageError::StateConflict);
        }
        insert_authenticator(&transaction, principal_id, authenticator, now_unix_ms)?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Lists active owner authenticators of one kind.
    pub fn owner_authenticators(
        &self,
        kind: AuthenticatorKind,
    ) -> StorageResult<Vec<OwnerAuthenticatorRecord>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r"SELECT authenticator_id, principal_id, authenticator_kind,
                      credential_lookup, credential_data, password_phc, state,
                      created_at_unix_ms, last_used_at_unix_ms, revoked_at_unix_ms,
                      state_commitment
               FROM smcv_owner_authenticators
               WHERE authenticator_kind = ?1 AND state = 'active'
               ORDER BY created_at_unix_ms, authenticator_id",
        )?;
        let rows = statement.query_map([kind.as_str()], parse_authenticator_row)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(parse_authenticator(row?)?);
        }
        Ok(records)
    }

    /// Atomically creates a server-side session with its successful-login audit.
    pub fn create_session(
        &self,
        session: &SessionInsert,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<()> {
        if session.idle_expires_at_unix_ms <= session.created_at_unix_ms
            || session.absolute_expires_at_unix_ms < session.idle_expires_at_unix_ms
        {
            return Err(StorageError::Conflict);
        }
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        transaction.execute(
            r"INSERT INTO smcv_sessions (
                   session_id, lookup_id, verifier, csrf_verifier, principal_id,
                   authenticator_id, auth_method, created_at_unix_ms, last_used_at_unix_ms,
                   idle_expires_at_unix_ms, absolute_expires_at_unix_ms,
                   recent_auth_at_unix_ms, revoked_at_unix_ms, state_commitment
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, NULL, ?12)",
            params![
                session.session_id.as_bytes(),
                session.lookup_id.as_slice(),
                session.verifier.as_slice(),
                session.csrf_verifier.as_slice(),
                session.principal_id.as_bytes(),
                session.authenticator_id.as_bytes(),
                session.auth_method.as_str(),
                session.created_at_unix_ms,
                session.idle_expires_at_unix_ms,
                session.absolute_expires_at_unix_ms,
                session.recent_auth_at_unix_ms,
                session.state_commitment.as_slice(),
            ],
        )?;
        if transaction.execute(
            r"UPDATE smcv_owner_authenticators
               SET last_used_at_unix_ms = ?1, state_commitment = ?2,
                   credential_data = COALESCE(?3, credential_data)
               WHERE authenticator_id = ?4 AND principal_id = ?5
                 AND state = 'active' AND revoked_at_unix_ms IS NULL",
            params![
                session.created_at_unix_ms,
                session.authenticator_state_commitment.as_slice(),
                session.authenticator_credential_data.as_deref(),
                session.authenticator_id.as_bytes(),
                session.principal_id.as_bytes(),
            ],
        )? != 1
        {
            return Err(StorageError::StateConflict);
        }
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Loads a session by its public random lookup component.
    pub fn session_by_lookup(&self, lookup_id: &[u8; 16]) -> StorageResult<Option<SessionRecord>> {
        let connection = self.lock()?;
        connection
            .query_row(
                r"SELECT session_id, lookup_id, verifier, csrf_verifier, principal_id,
                          authenticator_id, auth_method, created_at_unix_ms, last_used_at_unix_ms,
                          idle_expires_at_unix_ms, absolute_expires_at_unix_ms,
                          recent_auth_at_unix_ms, revoked_at_unix_ms, state_commitment
                   FROM smcv_sessions WHERE lookup_id = ?1",
                [lookup_id.as_slice()],
                parse_session_row,
            )
            .optional()?
            .map(parse_session)
            .transpose()
    }

    /// Loads one browser session by opaque server-side identity.
    pub fn session(&self, session_id: SessionId) -> StorageResult<SessionRecord> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                r"SELECT session_id, lookup_id, verifier, csrf_verifier, principal_id,
                          authenticator_id, auth_method, created_at_unix_ms, last_used_at_unix_ms,
                          idle_expires_at_unix_ms, absolute_expires_at_unix_ms,
                          recent_auth_at_unix_ms, revoked_at_unix_ms, state_commitment
                   FROM smcv_sessions WHERE session_id = ?1",
                [session_id.as_bytes()],
                parse_session_row,
            )
            .optional()?
            .ok_or(StorageError::NotInitialized)?;
        parse_session(row)
    }

    /// Advances a verified active session; revocation/expiry races fail closed.
    pub fn touch_session(
        &self,
        session_id: SessionId,
        expected_last_used_at_unix_ms: i64,
        now_unix_ms: i64,
        idle_expires_at_unix_ms: i64,
        recent_auth_at_unix_ms: i64,
        state_commitment: &[u8; 32],
    ) -> StorageResult<()> {
        let connection = self.lock()?;
        let changed = connection.execute(
            r"UPDATE smcv_sessions
               SET last_used_at_unix_ms = ?1, idle_expires_at_unix_ms = ?2,
                   recent_auth_at_unix_ms = ?3, state_commitment = ?4
               WHERE session_id = ?5 AND last_used_at_unix_ms = ?6
                 AND revoked_at_unix_ms IS NULL
                 AND idle_expires_at_unix_ms >= ?1
                 AND absolute_expires_at_unix_ms >= ?1
                 AND ?2 <= absolute_expires_at_unix_ms",
            params![
                now_unix_ms,
                idle_expires_at_unix_ms,
                recent_auth_at_unix_ms,
                state_commitment.as_slice(),
                session_id.as_bytes(),
                expected_last_used_at_unix_ms,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    /// Revokes one live session and commits logout audit atomically.
    pub fn revoke_session(
        &self,
        session_id: SessionId,
        expected_last_used_at_unix_ms: i64,
        revoked_at_unix_ms: i64,
        state_commitment: &[u8; 32],
        audit: &AuditRecord<'_>,
    ) -> StorageResult<()> {
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        let changed = transaction.execute(
            r"UPDATE smcv_sessions
               SET revoked_at_unix_ms = ?1, state_commitment = ?2
               WHERE session_id = ?3 AND last_used_at_unix_ms = ?4
                 AND revoked_at_unix_ms IS NULL",
            params![
                revoked_at_unix_ms,
                state_commitment.as_slice(),
                session_id.as_bytes(),
                expected_last_used_at_unix_ms,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Loads an application credential by public lookup component.
    pub fn application_credential_by_lookup(
        &self,
        lookup_id: &[u8; 12],
    ) -> StorageResult<Option<ApplicationCredentialRecord>> {
        let connection = self.lock()?;
        connection
            .query_row(
                r"SELECT credential_id, principal_id, lookup_id, verifier,
                          created_at_unix_ms, expires_at_unix_ms, last_used_at_unix_ms,
                          revoked_at_unix_ms, revision, state_commitment
                   FROM smcv_application_credentials WHERE lookup_id = ?1",
                [lookup_id.as_slice()],
                parse_application_credential_row,
            )
            .optional()?
            .map(parse_application_credential)
            .transpose()
    }

    /// Loads one application credential by opaque record identity.
    pub fn application_credential(
        &self,
        credential_id: CredentialId,
    ) -> StorageResult<ApplicationCredentialRecord> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                r"SELECT credential_id, principal_id, lookup_id, verifier,
                          created_at_unix_ms, expires_at_unix_ms, last_used_at_unix_ms,
                          revoked_at_unix_ms, revision, state_commitment
                   FROM smcv_application_credentials WHERE credential_id = ?1",
                [credential_id.as_bytes()],
                parse_application_credential_row,
            )
            .optional()?
            .ok_or(StorageError::NotInitialized)?;
        parse_application_credential(row)
    }

    /// Lists a bounded stable page of credentials for one service identity.
    pub fn application_credentials_after(
        &self,
        principal_id: PrincipalId,
        after: Option<(i64, CredentialId)>,
        limit: u16,
    ) -> StorageResult<Vec<ApplicationCredentialRecord>> {
        if limit == 0 {
            return Err(StorageError::InvalidData);
        }
        let (after_created, after_id) = after.map_or((i64::MIN, [0_u8; 16]), |(created, id)| {
            (created, *id.as_bytes())
        });
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r"SELECT credential_id, principal_id, lookup_id, verifier,
                      created_at_unix_ms, expires_at_unix_ms, last_used_at_unix_ms,
                      revoked_at_unix_ms, revision, state_commitment
                 FROM smcv_application_credentials
                WHERE principal_id = ?1
                  AND (created_at_unix_ms > ?2
                       OR (created_at_unix_ms = ?2 AND credential_id > ?3))
                ORDER BY created_at_unix_ms ASC, credential_id ASC LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                principal_id.as_bytes(),
                after_created,
                after_id.as_slice(),
                i64::from(limit),
            ],
            parse_application_credential_row,
        )?;
        let mut records = Vec::with_capacity(usize::from(limit));
        for row in rows {
            records.push(parse_application_credential(row?)?);
        }
        Ok(records)
    }

    /// Atomically persists a display-once application credential and audit.
    pub fn create_application_credential(
        &self,
        credential: &ApplicationCredentialInsert,
        audit: &AuditRecord<'_>,
    ) -> StorageResult<()> {
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        transaction.execute(
            r"INSERT INTO smcv_application_credentials (
                   credential_id, principal_id, lookup_id, verifier,
                   created_at_unix_ms, expires_at_unix_ms, last_used_at_unix_ms,
                   revoked_at_unix_ms, revision, state_commitment
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, 1, ?7)",
            params![
                credential.credential_id.as_bytes(),
                credential.principal_id.as_bytes(),
                credential.lookup_id.as_slice(),
                credential.verifier.as_slice(),
                credential.created_at_unix_ms,
                credential.expires_at_unix_ms,
                credential.state_commitment.as_slice(),
            ],
        )?;
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Marks credential use only if it remains active at the write point.
    pub fn mark_application_credential_used(
        &self,
        credential_id: CredentialId,
        expected_revision: u64,
        now_unix_ms: i64,
        state_commitment: &[u8; 32],
    ) -> StorageResult<u64> {
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        let next_revision_sql = i64::try_from(next_revision).map_err(|_| StorageError::Conflict)?;
        let expected_revision_sql =
            i64::try_from(expected_revision).map_err(|_| StorageError::Conflict)?;
        let connection = self.lock()?;
        let changed = connection.execute(
            r"UPDATE smcv_application_credentials
               SET last_used_at_unix_ms = ?1, revision = ?2, state_commitment = ?3
               WHERE credential_id = ?4 AND revision = ?5 AND revoked_at_unix_ms IS NULL
                 AND (expires_at_unix_ms IS NULL OR expires_at_unix_ms >= ?1)",
            params![
                now_unix_ms,
                next_revision_sql,
                state_commitment.as_slice(),
                credential_id.as_bytes(),
                expected_revision_sql,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        Ok(next_revision)
    }

    /// Revokes one application credential under optimistic revision control.
    pub fn revoke_application_credential(
        &self,
        credential_id: CredentialId,
        expected_revision: u64,
        revoked_at_unix_ms: i64,
        state_commitment: &[u8; 32],
        audit: &AuditRecord<'_>,
    ) -> StorageResult<u64> {
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        require_audit_head(&transaction, audit)?;
        let changed = transaction.execute(
            r"UPDATE smcv_application_credentials
               SET revoked_at_unix_ms = ?1, revision = ?2, state_commitment = ?3
               WHERE credential_id = ?4 AND revision = ?5 AND revoked_at_unix_ms IS NULL",
            params![
                revoked_at_unix_ms,
                i64::try_from(next_revision).map_err(|_| StorageError::Conflict)?,
                state_commitment.as_slice(),
                credential_id.as_bytes(),
                i64::try_from(expected_revision).map_err(|_| StorageError::Conflict)?,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        insert_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(next_revision)
    }
}

fn validate_authenticator(authenticator: &OwnerAuthenticatorInsert<'_>) -> StorageResult<()> {
    let valid = match authenticator.kind {
        AuthenticatorKind::Passkey => {
            authenticator.credential_lookup.is_some()
                && authenticator.credential_data.is_some()
                && authenticator.password_phc.is_none()
        }
        AuthenticatorKind::Password | AuthenticatorKind::Recovery => {
            authenticator.credential_lookup.is_none()
                && authenticator.credential_data.is_none()
                && authenticator.password_phc.is_some()
        }
    };
    if !valid {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

fn insert_authenticator(
    transaction: &rusqlite::Transaction<'_>,
    principal_id: PrincipalId,
    authenticator: &OwnerAuthenticatorInsert<'_>,
    now_unix_ms: i64,
) -> StorageResult<()> {
    transaction.execute(
        r"INSERT INTO smcv_owner_authenticators (
               authenticator_id, principal_id, authenticator_kind,
               credential_lookup, credential_data, password_phc, state,
               created_at_unix_ms, last_used_at_unix_ms, revoked_at_unix_ms,
               state_commitment
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, NULL, NULL, ?8)",
        params![
            authenticator.authenticator_id.as_bytes(),
            principal_id.as_bytes(),
            authenticator.kind.as_str(),
            authenticator.credential_lookup,
            authenticator.credential_data,
            authenticator.password_phc,
            now_unix_ms,
            authenticator.state_commitment.as_slice(),
        ],
    )?;
    Ok(())
}

type RawPrincipal = (Vec<u8>, String, String, i64, Vec<u8>);
type RawAuthenticator = (
    Vec<u8>,
    Vec<u8>,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    Vec<u8>,
);
type RawSession = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
    Vec<u8>,
);
type RawApplicationCredential = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    i64,
    Vec<u8>,
);

fn parse_principal_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawPrincipal> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn parse_principal(row: RawPrincipal) -> StorageResult<PrincipalRecord> {
    Ok(PrincipalRecord {
        principal_id: PrincipalId::from_uuid(parse_uuid(&row.0)?),
        kind: PrincipalKind::parse(&row.1)?,
        state: row.2,
        revision: u64::try_from(row.3).map_err(|_| StorageError::InvalidData)?,
        state_commitment: row.4.try_into().map_err(|_| StorageError::InvalidData)?,
    })
}

fn parse_authenticator_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawAuthenticator> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn parse_authenticator(row: RawAuthenticator) -> StorageResult<OwnerAuthenticatorRecord> {
    Ok(OwnerAuthenticatorRecord {
        authenticator_id: AuthenticatorId::from_uuid(parse_uuid(&row.0)?),
        principal_id: PrincipalId::from_uuid(parse_uuid(&row.1)?),
        kind: AuthenticatorKind::parse(&row.2)?,
        credential_lookup: row.3,
        credential_data: row.4,
        password_phc: row.5,
        state: row.6,
        created_at_unix_ms: row.7,
        last_used_at_unix_ms: row.8,
        revoked_at_unix_ms: row.9,
        state_commitment: row.10.try_into().map_err(|_| StorageError::InvalidData)?,
    })
}

fn parse_session_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawSession> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
    ))
}

fn parse_session(row: RawSession) -> StorageResult<SessionRecord> {
    Ok(SessionRecord {
        session_id: SessionId::from_uuid(parse_uuid(&row.0)?),
        lookup_id: row.1.try_into().map_err(|_| StorageError::InvalidData)?,
        verifier: row.2.try_into().map_err(|_| StorageError::InvalidData)?,
        csrf_verifier: row.3.try_into().map_err(|_| StorageError::InvalidData)?,
        principal_id: PrincipalId::from_uuid(parse_uuid(&row.4)?),
        authenticator_id: AuthenticatorId::from_uuid(parse_uuid(&row.5)?),
        auth_method: AuthenticatorKind::parse(&row.6)?,
        created_at_unix_ms: row.7,
        last_used_at_unix_ms: row.8,
        idle_expires_at_unix_ms: row.9,
        absolute_expires_at_unix_ms: row.10,
        recent_auth_at_unix_ms: row.11,
        revoked_at_unix_ms: row.12,
        state_commitment: row.13.try_into().map_err(|_| StorageError::InvalidData)?,
    })
}

fn parse_application_credential_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<RawApplicationCredential> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn parse_application_credential(
    row: RawApplicationCredential,
) -> StorageResult<ApplicationCredentialRecord> {
    Ok(ApplicationCredentialRecord {
        credential_id: CredentialId::from_uuid(parse_uuid(&row.0)?),
        principal_id: PrincipalId::from_uuid(parse_uuid(&row.1)?),
        lookup_id: row.2.try_into().map_err(|_| StorageError::InvalidData)?,
        verifier: row.3.try_into().map_err(|_| StorageError::InvalidData)?,
        created_at_unix_ms: row.4,
        expires_at_unix_ms: row.5,
        last_used_at_unix_ms: row.6,
        revoked_at_unix_ms: row.7,
        revision: u64::try_from(row.8).map_err(|_| StorageError::InvalidData)?,
        state_commitment: row.9.try_into().map_err(|_| StorageError::InvalidData)?,
    })
}

fn parse_uuid(bytes: &[u8]) -> StorageResult<Uuid> {
    Uuid::from_slice(bytes).map_err(|_| StorageError::InvalidData)
}

use rusqlite::{OptionalExtension, params};
use smcv_core::{ObjectId, PrincipalId};
use uuid::Uuid;

use crate::{SqliteStore, StorageError, StorageResult};

/// Durable reservation for one retry-safe create response identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdempotencyReservation {
    /// Stable response identity reused by every matching retry.
    pub response_id: ObjectId,
    /// Whether this call reused an earlier reservation.
    pub reused: bool,
}

impl SqliteStore {
    /// Reserves or reuses one principal-scoped idempotency response identity.
    ///
    /// # Errors
    ///
    /// Returns conflict when a raw-key verifier is reused with a different
    /// request fingerprint/response kind, and safe storage errors otherwise.
    #[allow(
        clippy::too_many_arguments,
        reason = "all persisted reservation fields are explicit"
    )]
    pub fn reserve_idempotency(
        &self,
        principal_id: PrincipalId,
        key_verifier: &[u8; 32],
        request_fingerprint: &[u8; 32],
        response_kind: &str,
        proposed_response_id: ObjectId,
        now_unix_ms: i64,
        expires_at_unix_ms: i64,
    ) -> StorageResult<IdempotencyReservation> {
        if response_kind.is_empty() || response_kind.len() > 32 || expires_at_unix_ms <= now_unix_ms
        {
            return Err(StorageError::Conflict);
        }
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "DELETE FROM smcv_idempotency_records WHERE expires_at_unix_ms < ?1",
            [now_unix_ms],
        )?;
        let existing = transaction
            .query_row(
                r"SELECT request_fingerprint, response_kind, response_id
                   FROM smcv_idempotency_records
                   WHERE principal_id = ?1 AND key_verifier = ?2",
                params![principal_id.as_bytes(), key_verifier.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some((fingerprint, kind, response_id)) = existing {
            let response_id = response_id.ok_or(StorageError::InvalidData)?;
            if fingerprint.as_slice() != request_fingerprint || kind != response_kind {
                return Err(StorageError::Conflict);
            }
            transaction.commit()?;
            return Ok(IdempotencyReservation {
                response_id: ObjectId::from_uuid(
                    Uuid::from_slice(&response_id).map_err(|_| StorageError::InvalidData)?,
                ),
                reused: true,
            });
        }
        transaction.execute(
            r"INSERT INTO smcv_idempotency_records VALUES
               (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                principal_id.as_bytes(),
                key_verifier.as_slice(),
                request_fingerprint.as_slice(),
                response_kind,
                proposed_response_id.as_bytes(),
                now_unix_ms,
                expires_at_unix_ms,
            ],
        )?;
        transaction.commit()?;
        Ok(IdempotencyReservation {
            response_id: proposed_response_id,
            reused: false,
        })
    }
}

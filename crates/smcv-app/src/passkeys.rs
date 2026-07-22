use std::{collections::HashMap, sync::Mutex, time::Duration};

use smcv_core::{Action, AuthenticatorId, CeremonyId, ObjectId, RequestId, ResourceKind};
use smcv_storage::{AuthenticatorKind, OwnerAuthenticatorInsert};
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

use crate::{
    AuthenticatedOwner, AuthenticationError, AuthorizationError, BrowserSessionSecrets,
    InitializedVault, RequestPrincipal, VaultOperationContext,
    authentication::{
        authenticator_commitment, map_storage, verify_authenticator_commitment,
        verify_principal_commitment,
    },
};

const CEREMONY_LIFETIME_MS: i64 = 5 * 60 * 1_000;
const MAX_PENDING_CEREMONIES: usize = 32;

/// Browser challenge paired with its opaque one-use server-side ceremony ID.
pub struct PasskeyChallenge<T> {
    /// Opaque reference required to finish exactly this ceremony.
    pub ceremony_id: CeremonyId,
    /// Standards-compliant `WebAuthn` options returned to the browser.
    pub options: T,
    /// Absolute server-side ceremony expiration.
    pub expires_at_unix_ms: i64,
}

struct RegistrationCeremony {
    principal_id: smcv_core::PrincipalId,
    session_id: smcv_core::SessionId,
    created_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    state: PasskeyRegistration,
}

struct AuthenticationCeremony {
    created_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    state: PasskeyAuthentication,
}

#[derive(Default)]
struct CeremonyState {
    registrations: HashMap<CeremonyId, RegistrationCeremony>,
    authentications: HashMap<CeremonyId, AuthenticationCeremony>,
}

/// Bounded, replay-resistant WebAuthn/passkey ceremony coordinator.
///
/// Challenge state remains server-side in process memory and is never accepted
/// back from the browser. A process restart safely invalidates pending work.
pub struct PasskeyService {
    webauthn: Webauthn,
    ceremonies: Mutex<CeremonyState>,
}

impl PasskeyService {
    /// Creates a passkey service pinned to one relying-party ID and exact origin.
    ///
    /// # Errors
    ///
    /// Returns invalid input if the HTTPS/loopback origin or RP relationship is
    /// invalid according to the `WebAuthn` implementation.
    pub fn new(rp_id: &str, origin: &str) -> Result<Self, AuthenticationError> {
        let origin = Url::parse(origin).map_err(|_| AuthenticationError::InvalidInput)?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|_| AuthenticationError::InvalidInput)?
            .rp_name("SMCV")
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|_| AuthenticationError::InvalidInput)?;
        Ok(Self {
            webauthn,
            ceremonies: Mutex::new(CeremonyState::default()),
        })
    }

    /// Begins recently-authenticated owner passkey enrollment.
    ///
    /// # Errors
    ///
    /// Returns rejected when recent authentication is absent and unavailable
    /// when bounded ceremony or durable authenticator state cannot be loaded.
    pub fn start_registration(
        &self,
        vault: &InitializedVault,
        owner: AuthenticatedOwner,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<PasskeyChallenge<CreationChallengeResponse>, AuthenticationError> {
        let _gate = vault
            .authorization_gate
            .read()
            .map_err(|_| AuthenticationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(vault, owner, now_unix_ms)?;
        if !owner.is_recent_at(now_unix_ms) {
            return Err(AuthenticationError::Rejected);
        }
        vault
            .authorize(
                RequestPrincipal::Owner(owner),
                Action::IdentityManage,
                ResourceKind::Namespace,
                ObjectId::from_uuid(vault.vault_id.as_uuid()),
                request_id,
                now_unix_ms,
            )
            .map_err(map_authorization)?;
        let records = vault
            .store
            .owner_authenticators(AuthenticatorKind::Passkey)
            .map_err(map_storage)?;
        let mut excluded = Vec::with_capacity(records.len());
        for record in records {
            verify_authenticator_commitment(vault, &record)?;
            let lookup = record
                .credential_lookup
                .ok_or(AuthenticationError::Integrity)?;
            excluded.push(CredentialID::from(lookup));
        }
        let exclusions = (!excluded.is_empty()).then_some(excluded);
        let (options, state) = self
            .webauthn
            .start_passkey_registration(
                owner.principal_id().as_uuid(),
                "owner",
                "SMCV owner",
                exclusions,
            )
            .map_err(|_| AuthenticationError::Rejected)?;
        let expires_at_unix_ms = now_unix_ms
            .checked_add(CEREMONY_LIFETIME_MS)
            .ok_or(AuthenticationError::Unavailable)?;
        let ceremony_id = CeremonyId::random();
        let mut ceremonies = self
            .ceremonies
            .lock()
            .map_err(|_| AuthenticationError::Unavailable)?;
        cleanup(&mut ceremonies, now_unix_ms);
        if ceremony_count(&ceremonies) >= MAX_PENDING_CEREMONIES {
            return Err(AuthenticationError::Unavailable);
        }
        ceremonies.registrations.insert(
            ceremony_id,
            RegistrationCeremony {
                principal_id: owner.principal_id(),
                session_id: owner.session_id(),
                created_at_unix_ms: now_unix_ms,
                expires_at_unix_ms,
                state,
            },
        );
        Ok(PasskeyChallenge {
            ceremony_id,
            options,
            expires_at_unix_ms,
        })
    }

    /// Finishes a one-use registration and persists only the public passkey.
    ///
    /// # Errors
    ///
    /// Returns rejected for replay, expiry, session mismatch, or invalid client
    /// data and integrity/unavailable for protected durable-state failures.
    pub fn finish_registration(
        &self,
        vault: &InitializedVault,
        owner: AuthenticatedOwner,
        ceremony_id: CeremonyId,
        response: &RegisterPublicKeyCredential,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<AuthenticatorId, AuthenticationError> {
        let _gate = vault
            .authorization_gate
            .read()
            .map_err(|_| AuthenticationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(vault, owner, now_unix_ms)?;
        if !owner.is_recent_at(now_unix_ms) {
            return Err(AuthenticationError::Rejected);
        }
        vault
            .authorize(
                RequestPrincipal::Owner(owner),
                Action::IdentityManage,
                ResourceKind::Namespace,
                ObjectId::from_uuid(vault.vault_id.as_uuid()),
                request_id,
                now_unix_ms,
            )
            .map_err(map_authorization)?;
        let ceremony = self.take_registration(ceremony_id)?;
        if now_unix_ms < ceremony.created_at_unix_ms
            || ceremony.expires_at_unix_ms < now_unix_ms
            || ceremony.principal_id != owner.principal_id()
            || ceremony.session_id != owner.session_id()
        {
            return Err(AuthenticationError::Rejected);
        }
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &ceremony.state)
            .map_err(|_| AuthenticationError::Rejected)?;
        let lookup: Vec<u8> = passkey.cred_id().to_vec();
        let serialized =
            serde_json::to_vec(&passkey).map_err(|_| AuthenticationError::Integrity)?;
        if lookup.is_empty() || lookup.len() > 1_024 || serialized.len() > 65_536 {
            return Err(AuthenticationError::InvalidInput);
        }
        let authenticator_id = AuthenticatorId::random();
        let commitment = authenticator_commitment(
            vault,
            authenticator_id,
            owner.principal_id(),
            AuthenticatorKind::Passkey,
            Some(&lookup),
            Some(&serialized),
            None,
            "active",
            now_unix_ms,
            None,
            None,
        )?;
        let insert = OwnerAuthenticatorInsert {
            authenticator_id,
            kind: AuthenticatorKind::Passkey,
            credential_lookup: Some(&lookup),
            credential_data: Some(&serialized),
            password_phc: None,
            state_commitment: commitment,
        };
        let audit = vault
            .build_audit(
                "passkey:register",
                "authenticator",
                Some(ObjectId::from_uuid(authenticator_id.as_uuid())),
                VaultOperationContext {
                    request_id,
                    actor_principal_id: Some(owner.principal_id()),
                    credential_kind: Some("session"),
                    credential_id: Some(ObjectId::from_uuid(owner.session_id().as_uuid())),
                    now_unix_ms,
                },
            )
            .map_err(|_| AuthenticationError::Unavailable)?;
        vault
            .store
            .add_owner_authenticator(owner.principal_id(), &insert, now_unix_ms, &audit)
            .map_err(map_storage)?;
        Ok(authenticator_id)
    }

    /// Begins owner passkey authentication without accepting an account hint.
    ///
    /// # Errors
    ///
    /// Returns rejected until at least one active passkey exists and unavailable
    /// when the bounded ceremony store cannot accept more work.
    pub fn start_authentication(
        &self,
        vault: &InitializedVault,
        now_unix_ms: i64,
    ) -> Result<PasskeyChallenge<RequestChallengeResponse>, AuthenticationError> {
        let records = vault
            .store
            .owner_authenticators(AuthenticatorKind::Passkey)
            .map_err(map_storage)?;
        let mut passkeys = Vec::with_capacity(records.len());
        for record in records {
            verify_authenticator_commitment(vault, &record)?;
            let data = record
                .credential_data
                .ok_or(AuthenticationError::Integrity)?;
            passkeys.push(
                serde_json::from_slice::<Passkey>(&data)
                    .map_err(|_| AuthenticationError::Integrity)?,
            );
        }
        if passkeys.is_empty() {
            return Err(AuthenticationError::Rejected);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| AuthenticationError::Rejected)?;
        let expires_at_unix_ms = now_unix_ms
            .checked_add(CEREMONY_LIFETIME_MS)
            .ok_or(AuthenticationError::Unavailable)?;
        let ceremony_id = CeremonyId::random();
        let mut ceremonies = self
            .ceremonies
            .lock()
            .map_err(|_| AuthenticationError::Unavailable)?;
        cleanup(&mut ceremonies, now_unix_ms);
        if ceremony_count(&ceremonies) >= MAX_PENDING_CEREMONIES {
            return Err(AuthenticationError::Unavailable);
        }
        ceremonies.authentications.insert(
            ceremony_id,
            AuthenticationCeremony {
                created_at_unix_ms: now_unix_ms,
                expires_at_unix_ms,
                state,
            },
        );
        Ok(PasskeyChallenge {
            ceremony_id,
            options,
            expires_at_unix_ms,
        })
    }

    /// Finishes one passkey assertion, updates its counter state, and logs in.
    ///
    /// # Errors
    ///
    /// Returns rejected for replay, expiry, invalid assertion, or a revoked
    /// credential and integrity/unavailable for protected state failures.
    pub fn finish_authentication(
        &self,
        vault: &InitializedVault,
        ceremony_id: CeremonyId,
        response: &PublicKeyCredential,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<BrowserSessionSecrets, AuthenticationError> {
        let ceremony = self.take_authentication(ceremony_id)?;
        if now_unix_ms < ceremony.created_at_unix_ms || ceremony.expires_at_unix_ms < now_unix_ms {
            return Err(AuthenticationError::Rejected);
        }
        let result = self
            .webauthn
            .finish_passkey_authentication(response, &ceremony.state)
            .map_err(|_| AuthenticationError::Rejected)?;
        let records = vault
            .store
            .owner_authenticators(AuthenticatorKind::Passkey)
            .map_err(map_storage)?;
        for record in records {
            verify_authenticator_commitment(vault, &record)?;
            if record.credential_lookup.as_deref() != Some(result.cred_id().as_ref()) {
                continue;
            }
            let mut passkey: Passkey = serde_json::from_slice(
                record
                    .credential_data
                    .as_deref()
                    .ok_or(AuthenticationError::Integrity)?,
            )
            .map_err(|_| AuthenticationError::Integrity)?;
            passkey
                .update_credential(&result)
                .ok_or(AuthenticationError::Rejected)?;
            let updated =
                serde_json::to_vec(&passkey).map_err(|_| AuthenticationError::Integrity)?;
            let owner = vault
                .store
                .principal(record.principal_id)
                .map_err(map_storage)?;
            verify_principal_commitment(vault, &owner)?;
            if owner.state != "active" {
                return Err(AuthenticationError::Rejected);
            }
            return vault.create_browser_session(
                &owner,
                &record,
                Some(updated),
                request_id,
                now_unix_ms,
            );
        }
        Err(AuthenticationError::Rejected)
    }

    fn take_registration(
        &self,
        ceremony_id: CeremonyId,
    ) -> Result<RegistrationCeremony, AuthenticationError> {
        self.ceremonies
            .lock()
            .map_err(|_| AuthenticationError::Unavailable)?
            .registrations
            .remove(&ceremony_id)
            .ok_or(AuthenticationError::Rejected)
    }

    fn take_authentication(
        &self,
        ceremony_id: CeremonyId,
    ) -> Result<AuthenticationCeremony, AuthenticationError> {
        self.ceremonies
            .lock()
            .map_err(|_| AuthenticationError::Unavailable)?
            .authentications
            .remove(&ceremony_id)
            .ok_or(AuthenticationError::Rejected)
    }
}

fn cleanup(ceremonies: &mut CeremonyState, now_unix_ms: i64) {
    ceremonies.registrations.retain(|_, value| {
        value.created_at_unix_ms <= now_unix_ms && value.expires_at_unix_ms >= now_unix_ms
    });
    ceremonies.authentications.retain(|_, value| {
        value.created_at_unix_ms <= now_unix_ms && value.expires_at_unix_ms >= now_unix_ms
    });
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "this mapper is passed directly to Result::map_err"
)]
fn map_authorization(error: AuthorizationError) -> AuthenticationError {
    match error {
        AuthorizationError::Denied | AuthorizationError::RecentAuthenticationRequired => {
            AuthenticationError::Rejected
        }
        AuthorizationError::InvalidInput => AuthenticationError::InvalidInput,
        AuthorizationError::Integrity => AuthenticationError::Integrity,
        AuthorizationError::Unavailable => AuthenticationError::Unavailable,
    }
}

fn ceremony_count(ceremonies: &CeremonyState) -> usize {
    ceremonies
        .registrations
        .len()
        .saturating_add(ceremonies.authentications.len())
}

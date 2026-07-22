use sha2::{Digest, Sha256};
use smcv_core::{
    Action, GrantId, GrantSpec, NamespaceId, ObjectId, PolicyId, PrincipalId, ProtectedBytes,
    ProtectedString, RequestId, ResourceKind, SecretId,
};
use smcv_crypto::{ObjectKind, state_commitment};
use smcv_storage::{AuthorizationSnapshot, PolicyBindingRecord, PolicyGrantRecord, PolicyInsert};
use thiserror::Error;

use crate::{
    AuthenticatedOwner, AuthenticatedService, InitializedVault, VaultOperationContext,
    authentication::map_storage,
};

const MAX_POLICY_LABEL_BYTES: usize = 128;
const MAX_AUTHORIZATION_RECORDS: usize = 10_000;

/// An authentication result accepted by the centralized policy boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestPrincipal {
    /// Sole human owner session.
    Owner(AuthenticatedOwner),
    /// Workload identity authenticated by one application credential.
    Service(AuthenticatedService),
}

impl RequestPrincipal {
    #[must_use]
    pub(crate) const fn principal_id(self) -> PrincipalId {
        match self {
            Self::Owner(owner) => owner.principal_id(),
            Self::Service(service) => service.principal_id(),
        }
    }

    pub(crate) const fn credential_attribution(self) -> (&'static str, ObjectId) {
        match self {
            Self::Owner(owner) => ("session", ObjectId::from_uuid(owner.session_id().as_uuid())),
            Self::Service(service) => (
                "application",
                ObjectId::from_uuid(service.credential_id().as_uuid()),
            ),
        }
    }
}

/// Protected owner-facing policy label.
pub struct PolicyMetadata {
    /// Human label encrypted at rest.
    pub label: ProtectedString,
}

/// Owner-visible policy state with decrypted display metadata.
pub struct PolicyDetails {
    /// Stable policy identifier.
    pub policy_id: PolicyId,
    /// Protected display label.
    pub label: ProtectedString,
    /// Durable lifecycle state.
    pub state: String,
    /// Optimistic revision.
    pub revision: u64,
}

/// Owner-visible rule attached to one policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyGrantSummary {
    pub grant_id: GrantId,
    pub action: Action,
    pub resource_kind: ResourceKind,
    pub resource_id: ObjectId,
    pub include_descendants: bool,
}

/// Owner-visible service binding attached to one policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyBindingSummary {
    pub principal_id: PrincipalId,
}

/// Complete safe rule inventory for one authenticated policy revision.
pub struct PolicyRuleSet {
    pub authorization_revision: u64,
    pub grants: Vec<PolicyGrantSummary>,
    pub bindings: Vec<PolicyBindingSummary>,
}

impl core::fmt::Debug for PolicyDetails {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PolicyDetails")
            .field("policy_id", &self.policy_id)
            .field("label", &"[REDACTED]")
            .field("state", &self.state)
            .field("revision", &self.revision)
            .finish()
    }
}

/// One service/action pair newly inheriting access after a namespace move.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveAccessDelta {
    /// Service principal whose reachable subtree would broaden.
    pub principal_id: PrincipalId,
    /// Newly inherited action.
    pub action: Action,
}

impl core::fmt::Debug for PolicyMetadata {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PolicyMetadata([REDACTED])")
    }
}

/// Safe authorization and policy-management failure categories.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// No current grant permits the requested operation.
    #[error("resource is unavailable")]
    Denied,
    /// A high-risk owner operation requires fresh authentication.
    #[error("recent authentication is required")]
    RecentAuthenticationRequired,
    /// Policy input is not in the closed v1 model.
    #[error("authorization input is invalid")]
    InvalidInput,
    /// Committed authorization or resource state does not authenticate.
    #[error("authorization state integrity check failed")]
    Integrity,
    /// Durable policy evaluation cannot be completed safely.
    #[error("authorization service is unavailable")]
    Unavailable,
}

impl InitializedVault {
    /// Computes the exact service/action broadening caused by a namespace move.
    ///
    /// # Errors
    ///
    /// Returns denied for an expired owner request and fail-closed integrity or
    /// unavailable errors for invalid hierarchy/policy state.
    pub fn preview_namespace_move(
        &self,
        owner: AuthenticatedOwner,
        namespace_id: NamespaceId,
        new_parent_namespace_id: Option<NamespaceId>,
        now_unix_ms: i64,
    ) -> Result<Vec<EffectiveAccessDelta>, AuthorizationError> {
        let _gate = self
            .authorization_gate
            .read()
            .map_err(|_| AuthorizationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
            .map_err(|_| AuthorizationError::Denied)?;
        self.preview_namespace_move_core(owner, namespace_id, new_parent_namespace_id, now_unix_ms)
    }

    fn preview_namespace_move_core(
        &self,
        owner: AuthenticatedOwner,
        namespace_id: NamespaceId,
        new_parent_namespace_id: Option<NamespaceId>,
        now_unix_ms: i64,
    ) -> Result<Vec<EffectiveAccessDelta>, AuthorizationError> {
        if !owner.is_valid_at(now_unix_ms) {
            return Err(AuthorizationError::Denied);
        }
        let old_ancestors = self
            .store
            .namespace_ancestors_inclusive(namespace_id)
            .map_err(map_authorization_storage)?;
        let mut new_ancestors = vec![namespace_id];
        if let Some(parent) = new_parent_namespace_id {
            let parent_ancestors = self
                .store
                .namespace_ancestors_inclusive(parent)
                .map_err(map_authorization_storage)?;
            if parent_ancestors.contains(&namespace_id) {
                return Err(AuthorizationError::InvalidInput);
            }
            new_ancestors.extend(parent_ancestors);
        }
        let snapshot = self.verified_authorization_snapshot()?;
        let mut delta = Vec::new();
        for binding in &snapshot.bindings {
            if !snapshot
                .policies
                .iter()
                .any(|policy| policy.policy_id == binding.policy_id && policy.state == "active")
            {
                continue;
            }
            for grant in snapshot.grants.iter().filter(|grant| {
                grant.policy_id == binding.policy_id
                    && grant.resource_kind == ResourceKind::Namespace
                    && grant.include_descendants
            }) {
                let target = NamespaceId::from_uuid(grant.resource_id.as_uuid());
                if !old_ancestors.contains(&target) && new_ancestors.contains(&target) {
                    delta.push(EffectiveAccessDelta {
                        principal_id: binding.principal_id,
                        action: grant.action,
                    });
                }
            }
        }
        delta.sort_by(|left, right| {
            left.principal_id
                .as_bytes()
                .cmp(right.principal_id.as_bytes())
                .then_with(|| left.action.as_str().cmp(right.action.as_str()))
        });
        delta.dedup();
        Ok(delta)
    }

    /// Moves a namespace only when the caller confirms the current access delta.
    ///
    /// # Errors
    ///
    /// Returns invalid input if the confirmed delta is stale or incomplete,
    /// requires recent auth for broadened access, and otherwise fails closed.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit move confirmation contract"
    )]
    pub fn move_namespace(
        &self,
        owner: AuthenticatedOwner,
        namespace_id: NamespaceId,
        expected_revision: u64,
        new_parent_namespace_id: Option<NamespaceId>,
        confirmed_delta: &[EffectiveAccessDelta],
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<u64, AuthorizationError> {
        let _gate = self
            .authorization_gate
            .write()
            .map_err(|_| AuthorizationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
            .map_err(|_| AuthorizationError::Denied)?;
        let actual = self.preview_namespace_move_core(
            owner,
            namespace_id,
            new_parent_namespace_id,
            now_unix_ms,
        )?;
        if actual != confirmed_delta {
            return Err(AuthorizationError::InvalidInput);
        }
        if !actual.is_empty() {
            require_recent(owner, now_unix_ms)?;
        }
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::NamespaceUpdate,
            ResourceKind::Namespace,
            ObjectId::from_uuid(namespace_id.as_uuid()),
            request_id,
            now_unix_ms,
        )?;
        self.move_namespace_core(
            namespace_id,
            expected_revision,
            new_parent_namespace_id,
            operation(RequestPrincipal::Owner(owner), request_id, now_unix_ms),
        )
        .map_err(|error| match error {
            crate::VaultError::Integrity => AuthorizationError::Integrity,
            crate::VaultError::InvalidInput => AuthorizationError::InvalidInput,
            crate::VaultError::NotFound | crate::VaultError::Conflict => AuthorizationError::Denied,
            crate::VaultError::Unavailable => AuthorizationError::Unavailable,
        })
    }

    /// Creates an empty named allow-only policy after recent owner authentication.
    ///
    /// # Errors
    ///
    /// Returns recent-auth/invalid-input failures or a safe durable-state error.
    pub fn create_policy(
        &self,
        owner: AuthenticatedOwner,
        metadata: &PolicyMetadata,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<PolicyId, AuthorizationError> {
        let _gate = self
            .authorization_gate
            .write()
            .map_err(|_| AuthorizationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
            .map_err(|_| AuthorizationError::Denied)?;
        require_recent(owner, now_unix_ms)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::PolicyManage,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )?;
        let label = metadata.label.expose().as_bytes();
        if label.is_empty() || label.len() > MAX_POLICY_LABEL_BYTES {
            return Err(AuthorizationError::InvalidInput);
        }
        let snapshot = self.verified_authorization_snapshot()?;
        let policy_id = PolicyId::random();
        let object_id = ObjectId::from_uuid(policy_id.as_uuid());
        let mut encoded = Vec::with_capacity(10 + label.len());
        encoded.extend_from_slice(b"SMCVPL01");
        encoded.extend_from_slice(
            &u16::try_from(label.len())
                .map_err(|_| AuthorizationError::InvalidInput)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(label);
        let encrypted = self
            .encrypt_record(
                ProtectedBytes::new(encoded),
                ObjectKind::PolicyMetadata,
                ObjectKind::WrappedPolicyMetadataKey,
                object_id,
                1,
            )
            .map_err(|_| AuthorizationError::Unavailable)?;
        let policy_commitment = policy_commitment(
            self,
            policy_id,
            1,
            "active",
            1,
            &encrypted,
            now_unix_ms,
            now_unix_ms,
        )?;
        let next_revision = snapshot
            .state
            .revision
            .checked_add(1)
            .ok_or(AuthorizationError::Unavailable)?;
        let graph_commitment = graph_commitment(
            self,
            &snapshot,
            next_revision,
            None,
            Some(graph_item(b'P', policy_id.as_bytes(), &policy_commitment)),
        )?;
        let audit = self
            .build_audit(
                "policy:create",
                "policy",
                Some(object_id),
                operation(RequestPrincipal::Owner(owner), request_id, now_unix_ms),
            )
            .map_err(|_| AuthorizationError::Unavailable)?;
        self.store
            .create_policy(
                &PolicyInsert {
                    policy_id,
                    metadata: encrypted,
                    state_commitment: policy_commitment,
                    created_at_unix_ms: now_unix_ms,
                },
                snapshot.state.revision,
                &graph_commitment,
                &audit,
            )
            .map_err(map_authorization_storage)?;
        Ok(policy_id)
    }

    /// Archives an allow-only policy with immediate next-request invalidation.
    ///
    /// # Errors
    ///
    /// Returns recent-authentication, stale revision, integrity, or unavailable
    /// failures without leaving policy and graph revisions inconsistent.
    pub fn archive_policy(
        &self,
        owner: AuthenticatedOwner,
        policy_id: PolicyId,
        expected_policy_revision: u64,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<u64, AuthorizationError> {
        let _gate = self
            .authorization_gate
            .write()
            .map_err(|_| AuthorizationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
            .map_err(|_| AuthorizationError::Denied)?;
        require_recent(owner, now_unix_ms)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::PolicyManage,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )?;
        let snapshot = self.verified_authorization_snapshot()?;
        let policy = snapshot
            .policies
            .iter()
            .find(|policy| policy.policy_id == policy_id)
            .ok_or(AuthorizationError::Denied)?;
        if policy.revision != expected_policy_revision || policy.state != "active" {
            return Err(AuthorizationError::Denied);
        }
        let next_policy_revision = expected_policy_revision
            .checked_add(1)
            .ok_or(AuthorizationError::Unavailable)?;
        let next_policy_commitment = policy_commitment(
            self,
            policy_id,
            next_policy_revision,
            "archived",
            policy.metadata_version,
            &policy.metadata,
            policy.created_at_unix_ms,
            now_unix_ms,
        )?;
        let next_authorization_revision = snapshot
            .state
            .revision
            .checked_add(1)
            .ok_or(AuthorizationError::Unavailable)?;
        let graph = graph_commitment(
            self,
            &snapshot,
            next_authorization_revision,
            Some((b'P', policy_id.as_bytes())),
            Some(graph_item(
                b'P',
                policy_id.as_bytes(),
                &next_policy_commitment,
            )),
        )?;
        let audit = self
            .build_audit(
                "policy:archive",
                "policy",
                Some(ObjectId::from_uuid(policy_id.as_uuid())),
                operation(RequestPrincipal::Owner(owner), request_id, now_unix_ms),
            )
            .map_err(|_| AuthorizationError::Unavailable)?;
        self.store
            .archive_policy(
                policy_id,
                expected_policy_revision,
                &next_policy_commitment,
                now_unix_ms,
                snapshot.state.revision,
                &graph,
                &audit,
            )
            .map_err(map_authorization_storage)?;
        Ok(next_policy_revision)
    }

    /// Adds one service-grantable allow rule to an existing policy.
    ///
    /// # Errors
    ///
    /// Rejects every owner-only action and invalid descendant shape before any
    /// write; stale graph state fails with a safe unavailable category.
    pub fn add_policy_grant(
        &self,
        owner: AuthenticatedOwner,
        spec: GrantSpec,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<GrantId, AuthorizationError> {
        let _gate = self
            .authorization_gate
            .write()
            .map_err(|_| AuthorizationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
            .map_err(|_| AuthorizationError::Denied)?;
        require_recent(owner, now_unix_ms)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::PolicyManage,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )?;
        if !spec.is_valid_for_service() {
            return Err(AuthorizationError::InvalidInput);
        }
        self.verify_grant_target(spec.resource_kind, spec.resource_id)?;
        let snapshot = self.verified_authorization_snapshot()?;
        if !snapshot
            .policies
            .iter()
            .any(|policy| policy.policy_id == spec.policy_id && policy.state == "active")
        {
            return Err(AuthorizationError::Denied);
        }
        let grant_id = GrantId::random();
        let commitment = grant_commitment(self, grant_id, spec, owner.principal_id(), now_unix_ms)?;
        let grant = PolicyGrantRecord {
            grant_id,
            policy_id: spec.policy_id,
            action: spec.action,
            resource_kind: spec.resource_kind,
            resource_id: spec.resource_id,
            include_descendants: spec.include_descendants,
            created_by_principal_id: owner.principal_id(),
            created_at_unix_ms: now_unix_ms,
            state_commitment: commitment,
        };
        let next_revision = snapshot
            .state
            .revision
            .checked_add(1)
            .ok_or(AuthorizationError::Unavailable)?;
        let graph_commitment = graph_commitment(
            self,
            &snapshot,
            next_revision,
            None,
            Some(graph_item(b'G', grant_id.as_bytes(), &commitment)),
        )?;
        let audit = self
            .build_audit(
                "policy:grant-add",
                "policy",
                Some(ObjectId::from_uuid(spec.policy_id.as_uuid())),
                operation(RequestPrincipal::Owner(owner), request_id, now_unix_ms),
            )
            .map_err(|_| AuthorizationError::Unavailable)?;
        self.store
            .add_policy_grant(&grant, snapshot.state.revision, &graph_commitment, &audit)
            .map_err(map_authorization_storage)?;
        Ok(grant_id)
    }

    /// Binds one policy to one active service identity.
    ///
    /// # Errors
    ///
    /// Returns recent-auth, invalid-state, integrity, or unavailable failures.
    pub fn bind_policy_to_service(
        &self,
        owner: AuthenticatedOwner,
        service_principal_id: PrincipalId,
        policy_id: PolicyId,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<(), AuthorizationError> {
        let _gate = self
            .authorization_gate
            .write()
            .map_err(|_| AuthorizationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
            .map_err(|_| AuthorizationError::Denied)?;
        require_recent(owner, now_unix_ms)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::PolicyManage,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )?;
        let principal = self
            .store
            .principal(service_principal_id)
            .map_err(map_authorization_storage)?;
        crate::authentication::verify_principal_commitment(self, &principal)
            .map_err(|_| AuthorizationError::Integrity)?;
        if principal.kind != smcv_storage::PrincipalKind::Service || principal.state != "active" {
            return Err(AuthorizationError::Denied);
        }
        let snapshot = self.verified_authorization_snapshot()?;
        if !snapshot
            .policies
            .iter()
            .any(|policy| policy.policy_id == policy_id && policy.state == "active")
        {
            return Err(AuthorizationError::Denied);
        }
        let commitment = binding_commitment(
            self,
            service_principal_id,
            policy_id,
            owner.principal_id(),
            now_unix_ms,
        )?;
        let binding = PolicyBindingRecord {
            principal_id: service_principal_id,
            policy_id,
            created_by_principal_id: owner.principal_id(),
            created_at_unix_ms: now_unix_ms,
            state_commitment: commitment,
        };
        let next_revision = snapshot
            .state
            .revision
            .checked_add(1)
            .ok_or(AuthorizationError::Unavailable)?;
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(service_principal_id.as_bytes());
        key.extend_from_slice(policy_id.as_bytes());
        let graph_commitment = graph_commitment(
            self,
            &snapshot,
            next_revision,
            None,
            Some(graph_item(b'B', &key, &commitment)),
        )?;
        let audit = self
            .build_audit(
                "policy:bind",
                "principal",
                Some(ObjectId::from_uuid(service_principal_id.as_uuid())),
                operation(RequestPrincipal::Owner(owner), request_id, now_unix_ms),
            )
            .map_err(|_| AuthorizationError::Unavailable)?;
        self.store
            .bind_policy(&binding, snapshot.state.revision, &graph_commitment, &audit)
            .map_err(map_authorization_storage)?;
        Ok(())
    }

    /// Reads one policy's protected display metadata and safe state.
    ///
    /// # Errors
    ///
    /// Returns a uniform denial for absent policy state and fails closed on
    /// session, graph, envelope, or durable-state integrity failures.
    pub fn read_policy(
        &self,
        owner: AuthenticatedOwner,
        policy_id: PolicyId,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<PolicyDetails, AuthorizationError> {
        let _gate = self
            .authorization_gate
            .read()
            .map_err(|_| AuthorizationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
            .map_err(|_| AuthorizationError::Denied)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::PolicyRead,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )?;
        let snapshot = self.verified_authorization_snapshot()?;
        let policy = snapshot
            .policies
            .into_iter()
            .find(|candidate| candidate.policy_id == policy_id)
            .ok_or(AuthorizationError::Denied)?;
        let plaintext = self
            .decrypt_record(
                &policy.metadata,
                ObjectKind::PolicyMetadata,
                ObjectKind::WrappedPolicyMetadataKey,
                ObjectId::from_uuid(policy_id.as_uuid()),
                policy.metadata_version,
            )
            .map_err(|_| AuthorizationError::Integrity)?;
        let label = decode_policy_label(&plaintext)?;
        Ok(PolicyDetails {
            policy_id,
            label,
            state: policy.state,
            revision: policy.revision,
        })
    }

    /// Lists a bounded stable page of policies with protected display labels.
    ///
    /// # Errors
    ///
    /// Returns denied for stale owner authority, invalid input for page bounds,
    /// and integrity failure for any graph or metadata mismatch.
    pub fn policies(
        &self,
        owner: AuthenticatedOwner,
        after_policy_id: Option<PolicyId>,
        limit: u16,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<Vec<PolicyDetails>, AuthorizationError> {
        if !(1..=100).contains(&limit) {
            return Err(AuthorizationError::InvalidInput);
        }
        let _gate = self
            .authorization_gate
            .read()
            .map_err(|_| AuthorizationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
            .map_err(|_| AuthorizationError::Denied)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::PolicyRead,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )?;
        let snapshot = self.verified_authorization_snapshot()?;
        let mut details = Vec::with_capacity(usize::from(limit));
        for policy in snapshot
            .policies
            .into_iter()
            .filter(|policy| after_policy_id.is_none_or(|after| policy.policy_id > after))
            .take(usize::from(limit))
        {
            let plaintext = self
                .decrypt_record(
                    &policy.metadata,
                    ObjectKind::PolicyMetadata,
                    ObjectKind::WrappedPolicyMetadataKey,
                    ObjectId::from_uuid(policy.policy_id.as_uuid()),
                    policy.metadata_version,
                )
                .map_err(|_| AuthorizationError::Integrity)?;
            details.push(PolicyDetails {
                policy_id: policy.policy_id,
                label: decode_policy_label(&plaintext)?,
                state: policy.state,
                revision: policy.revision,
            });
        }
        Ok(details)
    }

    /// Reads the exact grants and service bindings for one policy.
    ///
    /// # Errors
    ///
    /// Returns a uniform denial for absent policy state and fails closed for
    /// stale owner or graph integrity failures.
    pub fn policy_rules(
        &self,
        owner: AuthenticatedOwner,
        policy_id: PolicyId,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<PolicyRuleSet, AuthorizationError> {
        let _gate = self
            .authorization_gate
            .read()
            .map_err(|_| AuthorizationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
            .map_err(|_| AuthorizationError::Denied)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::PolicyRead,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )?;
        let snapshot = self.verified_authorization_snapshot()?;
        if !snapshot
            .policies
            .iter()
            .any(|policy| policy.policy_id == policy_id)
        {
            return Err(AuthorizationError::Denied);
        }
        Ok(PolicyRuleSet {
            authorization_revision: snapshot.state.revision,
            grants: snapshot
                .grants
                .into_iter()
                .filter(|grant| grant.policy_id == policy_id)
                .map(|grant| PolicyGrantSummary {
                    grant_id: grant.grant_id,
                    action: grant.action,
                    resource_kind: grant.resource_kind,
                    resource_id: grant.resource_id,
                    include_descendants: grant.include_descendants,
                })
                .collect(),
            bindings: snapshot
                .bindings
                .into_iter()
                .filter(|binding| binding.policy_id == policy_id)
                .map(|binding| PolicyBindingSummary {
                    principal_id: binding.principal_id,
                })
                .collect(),
        })
    }

    /// Computes the closed service-action set currently effective on a target.
    ///
    /// # Errors
    ///
    /// Returns denied for stale owner/service state and fails closed when the
    /// committed authorization graph cannot be authenticated.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit owner, service, resource, request, and time boundary"
    )]
    pub fn effective_service_actions(
        &self,
        owner: AuthenticatedOwner,
        service_principal_id: PrincipalId,
        resource_kind: ResourceKind,
        resource_id: ObjectId,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<Vec<Action>, AuthorizationError> {
        let _gate = self
            .authorization_gate
            .read()
            .map_err(|_| AuthorizationError::Unavailable)?;
        crate::authentication::verify_owner_context_active(self, owner, now_unix_ms)
            .map_err(|_| AuthorizationError::Denied)?;
        self.authorize(
            RequestPrincipal::Owner(owner),
            Action::EffectiveAccessRead,
            ResourceKind::Namespace,
            ObjectId::from_uuid(self.vault_id.as_uuid()),
            request_id,
            now_unix_ms,
        )?;
        let principal = self
            .store
            .principal(service_principal_id)
            .map_err(map_authorization_storage)?;
        crate::authentication::verify_principal_commitment(self, &principal)
            .map_err(|_| AuthorizationError::Integrity)?;
        if principal.kind != smcv_storage::PrincipalKind::Service || principal.state != "active" {
            return Err(AuthorizationError::Denied);
        }
        let mut actions = Vec::new();
        for action in Action::ALL {
            if action.is_service_grantable()
                && self.service_is_allowed(
                    service_principal_id,
                    action,
                    resource_kind,
                    resource_id,
                )?
            {
                actions.push(action);
            }
        }
        Ok(actions)
    }

    /// Makes one centralized authorization decision and audits denials.
    ///
    /// # Errors
    ///
    /// Returns denied with no existence distinction, recent-authentication
    /// required for high-risk owner actions, and fail-closed integrity errors.
    pub(crate) fn authorize(
        &self,
        principal: RequestPrincipal,
        action: Action,
        resource_kind: ResourceKind,
        resource_id: ObjectId,
        request_id: RequestId,
        now_unix_ms: i64,
    ) -> Result<(), AuthorizationError> {
        let decision = match principal {
            RequestPrincipal::Owner(owner) => {
                if !owner.is_valid_at(now_unix_ms) {
                    Err(AuthorizationError::Denied)
                } else if action_requires_recent(action) && !owner.is_recent_at(now_unix_ms) {
                    Err(AuthorizationError::RecentAuthenticationRequired)
                } else {
                    Ok(())
                }
            }
            RequestPrincipal::Service(service) => {
                if !action.is_service_grantable() {
                    Err(AuthorizationError::Denied)
                } else if self.service_is_allowed(
                    service.principal_id(),
                    action,
                    resource_kind,
                    resource_id,
                )? {
                    Ok(())
                } else {
                    Err(AuthorizationError::Denied)
                }
            }
        };
        let outcome = if decision.is_ok() {
            "allowed"
        } else {
            "denied"
        };
        let audit = self
            .build_audit_outcome(
                action.as_str(),
                resource_kind.as_str(),
                Some(resource_id),
                outcome,
                operation(principal, request_id, now_unix_ms),
            )
            .map_err(|_| AuthorizationError::Unavailable)?;
        self.store
            .append_audit(&audit)
            .map_err(map_authorization_storage)?;
        decision
    }

    fn service_is_allowed(
        &self,
        principal_id: PrincipalId,
        action: Action,
        resource_kind: ResourceKind,
        resource_id: ObjectId,
    ) -> Result<bool, AuthorizationError> {
        let snapshot = self.verified_authorization_snapshot()?;
        let active_policies: Vec<PolicyId> = snapshot
            .bindings
            .iter()
            .filter(|binding| binding.principal_id == principal_id)
            .map(|binding| binding.policy_id)
            .filter(|policy_id| {
                snapshot
                    .policies
                    .iter()
                    .any(|policy| policy.policy_id == *policy_id && policy.state == "active")
            })
            .collect();
        let ancestors = self.resource_namespace_ancestors(resource_kind, resource_id)?;
        Ok(snapshot.grants.iter().any(|grant| {
            grant.action == action
                && active_policies.contains(&grant.policy_id)
                && ((grant.resource_kind == resource_kind && grant.resource_id == resource_id)
                    || (grant.resource_kind == ResourceKind::Namespace
                        && ancestors.iter().any(|ancestor| {
                            grant.resource_id.as_uuid() == ancestor.as_uuid()
                                && (grant.include_descendants
                                    || resource_kind == ResourceKind::Namespace
                                        && resource_id.as_uuid() == ancestor.as_uuid())
                        })))
        }))
    }

    fn resource_namespace_ancestors(
        &self,
        resource_kind: ResourceKind,
        resource_id: ObjectId,
    ) -> Result<Vec<NamespaceId>, AuthorizationError> {
        let namespace_id = match resource_kind {
            ResourceKind::Namespace => NamespaceId::from_uuid(resource_id.as_uuid()),
            ResourceKind::Secret => {
                let secret = self
                    .store
                    .secret(SecretId::from_uuid(resource_id.as_uuid()))
                    .map_err(|_| AuthorizationError::Denied)?;
                self.verify_secret_state(&secret)
                    .map_err(|_| AuthorizationError::Integrity)?;
                secret.namespace_id
            }
        };
        let ancestors = self
            .store
            .namespace_ancestors_inclusive(namespace_id)
            .map_err(|_| AuthorizationError::Denied)?;
        for ancestor in &ancestors {
            let state = self
                .store
                .namespace(*ancestor)
                .map_err(|_| AuthorizationError::Denied)?;
            self.verify_namespace_state(&state)
                .map_err(|_| AuthorizationError::Integrity)?;
        }
        Ok(ancestors)
    }

    fn verify_grant_target(
        &self,
        resource_kind: ResourceKind,
        resource_id: ObjectId,
    ) -> Result<(), AuthorizationError> {
        match resource_kind {
            ResourceKind::Namespace => {
                let record = self
                    .store
                    .namespace(NamespaceId::from_uuid(resource_id.as_uuid()))
                    .map_err(|_| AuthorizationError::Denied)?;
                self.verify_namespace_state(&record)
                    .map_err(|_| AuthorizationError::Integrity)?;
            }
            ResourceKind::Secret => {
                let record = self
                    .store
                    .secret(SecretId::from_uuid(resource_id.as_uuid()))
                    .map_err(|_| AuthorizationError::Denied)?;
                self.verify_secret_state(&record)
                    .map_err(|_| AuthorizationError::Integrity)?;
            }
        }
        Ok(())
    }

    pub(crate) fn verified_authorization_snapshot(
        &self,
    ) -> Result<AuthorizationSnapshot, AuthorizationError> {
        let snapshot = self
            .store
            .authorization_snapshot()
            .map_err(map_authorization_storage)?;
        let count = snapshot
            .policies
            .len()
            .saturating_add(snapshot.grants.len())
            .saturating_add(snapshot.bindings.len());
        if count > MAX_AUTHORIZATION_RECORDS {
            return Err(AuthorizationError::Unavailable);
        }
        for policy in &snapshot.policies {
            if policy_commitment(
                self,
                policy.policy_id,
                policy.revision,
                &policy.state,
                policy.metadata_version,
                &policy.metadata,
                policy.created_at_unix_ms,
                policy.updated_at_unix_ms,
            )? != policy.state_commitment
            {
                return Err(AuthorizationError::Integrity);
            }
        }
        for grant in &snapshot.grants {
            let spec = GrantSpec {
                policy_id: grant.policy_id,
                action: grant.action,
                resource_kind: grant.resource_kind,
                resource_id: grant.resource_id,
                include_descendants: grant.include_descendants,
            };
            if !spec.is_valid_for_service()
                || grant_commitment(
                    self,
                    grant.grant_id,
                    spec,
                    grant.created_by_principal_id,
                    grant.created_at_unix_ms,
                )? != grant.state_commitment
            {
                return Err(AuthorizationError::Integrity);
            }
        }
        for binding in &snapshot.bindings {
            if binding_commitment(
                self,
                binding.principal_id,
                binding.policy_id,
                binding.created_by_principal_id,
                binding.created_at_unix_ms,
            )? != binding.state_commitment
            {
                return Err(AuthorizationError::Integrity);
            }
        }
        if graph_commitment(self, &snapshot, snapshot.state.revision, None, None)?
            != snapshot.state.state_commitment
        {
            return Err(AuthorizationError::Integrity);
        }
        Ok(snapshot)
    }
}

fn require_recent(owner: AuthenticatedOwner, now_unix_ms: i64) -> Result<(), AuthorizationError> {
    if owner.is_recent_at(now_unix_ms) {
        Ok(())
    } else {
        Err(AuthorizationError::RecentAuthenticationRequired)
    }
}

fn action_requires_recent(action: Action) -> bool {
    matches!(
        action,
        Action::SecretValueRead
            | Action::SecretHistoryRead
            | Action::SecretVersionRead
            | Action::SecretPurge
            | Action::CredentialIssue
            | Action::CredentialRevoke
            | Action::PolicyManage
            | Action::BackupCreate
            | Action::BackupRestore
            | Action::KeyRotate
            | Action::VaultConfigure
            | Action::VaultLock
    )
}

fn operation(
    principal: RequestPrincipal,
    request_id: RequestId,
    now_unix_ms: i64,
) -> VaultOperationContext {
    let (credential_kind, credential_id) = principal.credential_attribution();
    VaultOperationContext {
        request_id,
        actor_principal_id: Some(principal.principal_id()),
        credential_kind: Some(credential_kind),
        credential_id: Some(credential_id),
        now_unix_ms,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn policy_commitment(
    vault: &InitializedVault,
    policy_id: PolicyId,
    revision: u64,
    state: &str,
    metadata_version: u64,
    metadata: &smcv_storage::EncryptedRecord,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
) -> Result<[u8; 32], AuthorizationError> {
    let envelope_digest = Sha256::digest(
        [
            metadata.nonce.as_slice(),
            metadata.ciphertext.as_slice(),
            metadata.dek_nonce.as_slice(),
            metadata.wrapped_dek.as_slice(),
            &metadata.kek_version.to_be_bytes(),
        ]
        .concat(),
    );
    let canonical = format!(
        "policy\0{policy_id}\0{revision}\0{state}\0{metadata_version}\0{}\0{created_at_unix_ms}\0{updated_at_unix_ms}",
        hex::encode(envelope_digest),
    );
    commit(vault, canonical.as_bytes())
}

fn grant_commitment(
    vault: &InitializedVault,
    grant_id: GrantId,
    spec: GrantSpec,
    actor: PrincipalId,
    created_at_unix_ms: i64,
) -> Result<[u8; 32], AuthorizationError> {
    let canonical = format!(
        "grant\0{grant_id}\0{}\0{}\0{}\0{}\0{}\0{actor}\0{created_at_unix_ms}",
        spec.policy_id,
        spec.action.as_str(),
        spec.resource_kind.as_str(),
        spec.resource_id,
        u8::from(spec.include_descendants),
    );
    commit(vault, canonical.as_bytes())
}

fn binding_commitment(
    vault: &InitializedVault,
    principal_id: PrincipalId,
    policy_id: PolicyId,
    actor: PrincipalId,
    created_at_unix_ms: i64,
) -> Result<[u8; 32], AuthorizationError> {
    let canonical = format!("binding\0{principal_id}\0{policy_id}\0{actor}\0{created_at_unix_ms}");
    commit(vault, canonical.as_bytes())
}

fn commit(vault: &InitializedVault, canonical: &[u8]) -> Result<[u8; 32], AuthorizationError> {
    state_commitment(vault.audit_key(), canonical)
        .map(|value| *value.as_bytes())
        .map_err(|_| AuthorizationError::Integrity)
}

fn graph_item(tag: u8, key: &[u8], commitment: &[u8; 32]) -> Vec<u8> {
    let mut item = Vec::with_capacity(1 + key.len() + commitment.len());
    item.push(tag);
    item.extend_from_slice(key);
    item.extend_from_slice(commitment);
    item
}

fn graph_commitment(
    vault: &InitializedVault,
    snapshot: &AuthorizationSnapshot,
    revision: u64,
    exclude: Option<(u8, &[u8])>,
    extra: Option<Vec<u8>>,
) -> Result<[u8; 32], AuthorizationError> {
    let mut items = Vec::with_capacity(
        snapshot
            .policies
            .len()
            .saturating_add(snapshot.grants.len())
            .saturating_add(snapshot.bindings.len())
            .saturating_add(usize::from(extra.is_some())),
    );
    for policy in &snapshot.policies {
        if exclude.is_some_and(|(tag, key)| tag == b'P' && key == policy.policy_id.as_bytes()) {
            continue;
        }
        items.push(graph_item(
            b'P',
            policy.policy_id.as_bytes(),
            &policy.state_commitment,
        ));
    }
    for grant in &snapshot.grants {
        if exclude.is_some_and(|(tag, key)| tag == b'G' && key == grant.grant_id.as_bytes()) {
            continue;
        }
        items.push(graph_item(
            b'G',
            grant.grant_id.as_bytes(),
            &grant.state_commitment,
        ));
    }
    for binding in &snapshot.bindings {
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(binding.principal_id.as_bytes());
        key.extend_from_slice(binding.policy_id.as_bytes());
        if exclude.is_some_and(|(tag, excluded_key)| tag == b'B' && excluded_key == key) {
            continue;
        }
        items.push(graph_item(b'B', &key, &binding.state_commitment));
    }
    if let Some(extra) = extra {
        items.push(extra);
    }
    if items.is_empty() && revision == 1 {
        return commit(vault, b"authorization-graph\0v1\0revision\0\x31\0empty");
    }
    items.sort();
    let mut digest = Sha256::new();
    for item in items {
        digest.update(
            u32::try_from(item.len())
                .map_err(|_| AuthorizationError::Unavailable)?
                .to_be_bytes(),
        );
        digest.update(item);
    }
    let canonical = format!(
        "authorization-graph\0v1\0revision\0{revision}\0{}",
        hex::encode(digest.finalize())
    );
    commit(vault, canonical.as_bytes())
}

pub(crate) fn portable_authorization_commitment(
    vault: &InitializedVault,
    policies: &[smcv_storage::PortablePolicy],
    grants: &[PolicyGrantRecord],
    bindings: &[PolicyBindingRecord],
    revision: u64,
) -> Result<[u8; 32], AuthorizationError> {
    let mut items = Vec::with_capacity(
        policies
            .len()
            .saturating_add(grants.len())
            .saturating_add(bindings.len()),
    );
    for policy in policies {
        items.push(graph_item(
            b'P',
            policy.policy_id.as_bytes(),
            &policy.state_commitment,
        ));
    }
    for grant in grants {
        items.push(graph_item(
            b'G',
            grant.grant_id.as_bytes(),
            &grant.state_commitment,
        ));
    }
    for binding in bindings {
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(binding.principal_id.as_bytes());
        key.extend_from_slice(binding.policy_id.as_bytes());
        items.push(graph_item(b'B', &key, &binding.state_commitment));
    }
    if items.is_empty() && revision == 1 {
        return commit(vault, b"authorization-graph\0v1\0revision\0\x31\0empty");
    }
    items.sort();
    let mut digest = Sha256::new();
    for item in items {
        digest.update(
            u32::try_from(item.len())
                .map_err(|_| AuthorizationError::Unavailable)?
                .to_be_bytes(),
        );
        digest.update(item);
    }
    let canonical = format!(
        "authorization-graph\0v1\0revision\0{revision}\0{}",
        hex::encode(digest.finalize())
    );
    commit(vault, canonical.as_bytes())
}

fn map_authorization_storage(error: smcv_storage::StorageError) -> AuthorizationError {
    match map_storage(error) {
        crate::AuthenticationError::Integrity => AuthorizationError::Integrity,
        crate::AuthenticationError::Rejected => AuthorizationError::Denied,
        crate::AuthenticationError::InvalidInput => AuthorizationError::InvalidInput,
        crate::AuthenticationError::Unavailable => AuthorizationError::Unavailable,
    }
}

fn decode_policy_label(plaintext: &ProtectedBytes) -> Result<ProtectedString, AuthorizationError> {
    let bytes = plaintext.expose();
    if bytes.len() < 10 || !bytes.starts_with(b"SMCVPL01") {
        return Err(AuthorizationError::Integrity);
    }
    let length = usize::from(u16::from_be_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| AuthorizationError::Integrity)?,
    ));
    if length == 0 || length > MAX_POLICY_LABEL_BYTES || bytes.len() != 10 + length {
        return Err(AuthorizationError::Integrity);
    }
    String::from_utf8(bytes[10..].to_vec())
        .map(ProtectedString::new)
        .map_err(|_| AuthorizationError::Integrity)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use smcv_core::{
        Action, GrantSpec, ObjectId, ProtectedBytes, ProtectedString, RequestId, ResourceKind,
        SecretSchedule,
    };
    use tempfile::TempDir;

    use crate::{
        IdempotencyInput, LocalSetupCapability, MetadataInput, PolicyMetadata, RequestPrincipal,
        ServiceIdentityMetadata, initialize_vault,
    };

    fn metadata(name: &str) -> MetadataInput {
        MetadataInput {
            name: ProtectedString::new(String::from(name)),
            description: None,
            username: None,
            tags: Vec::new(),
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "end-to-end authorization matrix fixture"
    )]
    fn exact_and_descendant_grants_do_not_leak_to_siblings_or_owner_actions() {
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
        let password = ProtectedString::new(String::from("synthetic long password"));
        vault
            .enroll_local_owner(
                LocalSetupCapability::for_local_cli(),
                &password,
                RequestId::random(),
                1_800_000_001_000,
            )
            .unwrap_or_else(|error| panic!("synthetic owner must enroll: {error}"));
        let session = vault
            .login_with_password(&password, RequestId::random(), 1_800_000_002_000)
            .unwrap_or_else(|error| panic!("synthetic owner must login: {error}"));
        let owner = vault
            .authenticate_browser_session(
                &session.session_token,
                Some(&session.csrf_token),
                true,
                1_800_000_003_000,
            )
            .unwrap_or_else(|error| panic!("synthetic session must authenticate: {error}"));
        let owner_vault = vault
            .authorized(
                RequestPrincipal::Owner(owner),
                RequestId::random(),
                1_800_000_004_000,
            )
            .unwrap_or_else(|error| panic!("owner authorization must succeed: {error}"));
        let namespace = owner_vault
            .create_namespace(None, &metadata("synthetic namespace"))
            .unwrap_or_else(|error| panic!("synthetic namespace must create: {error}"));
        let first = owner_vault
            .create_secret(
                namespace,
                &metadata("first"),
                ProtectedBytes::new(b"first-value".to_vec()),
                SecretSchedule::default(),
            )
            .unwrap_or_else(|error| panic!("first secret must create: {error}"));
        let sibling = owner_vault
            .create_secret(
                namespace,
                &metadata("sibling"),
                ProtectedBytes::new(b"sibling-value".to_vec()),
                SecretSchedule::default(),
            )
            .unwrap_or_else(|error| panic!("sibling secret must create: {error}"));
        owner_vault
            .update_secret(
                first.secret_id,
                1,
                1,
                ProtectedBytes::new(b"second-value".to_vec()),
                SecretSchedule::default(),
            )
            .unwrap_or_else(|error| panic!("second version must append: {error}"));
        let history = owner_vault
            .secret_version_history(first.secret_id, 0, 100)
            .unwrap_or_else(|error| panic!("version history must list: {error}"));
        assert_eq!(
            history
                .iter()
                .map(|record| record.version)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        let historical = owner_vault
            .reveal_secret_version(first.secret_id, 1)
            .unwrap_or_else(|error| panic!("historical version must reveal: {error}"));
        assert_eq!(historical.expose(), b"first-value");
        let broader_parent = owner_vault
            .create_namespace(None, &metadata("broader parent"))
            .unwrap_or_else(|error| panic!("broader parent must create: {error}"));
        let idempotency = IdempotencyInput {
            key: ProtectedString::new(String::from("synthetic-idempotency-key")),
            canonical_request: ProtectedBytes::new(b"synthetic canonical request".to_vec()),
        };
        let idempotent_first = owner_vault
            .create_namespace_idempotent(None, &metadata("idempotent"), &idempotency)
            .unwrap_or_else(|error| panic!("idempotent namespace must create: {error}"));
        let idempotent_retry = owner_vault
            .create_namespace_idempotent(None, &metadata("idempotent"), &idempotency)
            .unwrap_or_else(|error| panic!("matching retry must resolve: {error}"));
        assert_eq!(idempotent_first, idempotent_retry);
        assert!(
            owner_vault
                .create_namespace_idempotent(
                    None,
                    &metadata("different"),
                    &IdempotencyInput {
                        key: ProtectedString::new(String::from("synthetic-idempotency-key")),
                        canonical_request: ProtectedBytes::new(
                            b"different canonical request".to_vec(),
                        ),
                    },
                )
                .is_err()
        );
        drop(owner_vault);

        let service = vault
            .create_service_identity(
                owner,
                &ServiceIdentityMetadata {
                    label: ProtectedString::new(String::from("synthetic reader")),
                    description: None,
                },
                RequestId::random(),
                1_800_000_005_000,
            )
            .unwrap_or_else(|error| panic!("synthetic service must create: {error}"));
        let policy = vault
            .create_policy(
                owner,
                &PolicyMetadata {
                    label: ProtectedString::new(String::from("exact read")),
                },
                RequestId::random(),
                1_800_000_006_000,
            )
            .unwrap_or_else(|error| panic!("synthetic policy must create: {error}"));
        let policy_inventory = vault
            .policies(owner, None, 100, RequestId::random(), 1_800_000_006_500)
            .unwrap_or_else(|error| panic!("policy inventory must read: {error}"));
        assert_eq!(policy_inventory.len(), 1);
        assert_eq!(policy_inventory[0].policy_id, policy);
        assert_eq!(policy_inventory[0].label.expose(), "exact read");
        let empty_rules = vault
            .policy_rules(owner, policy, RequestId::random(), 1_800_000_006_600)
            .unwrap_or_else(|error| panic!("empty policy rules must read: {error}"));
        assert!(empty_rules.grants.is_empty());
        assert!(empty_rules.bindings.is_empty());
        vault
            .add_policy_grant(
                owner,
                GrantSpec {
                    policy_id: policy,
                    action: Action::SecretValueRead,
                    resource_kind: ResourceKind::Secret,
                    resource_id: ObjectId::from_uuid(first.secret_id.as_uuid()),
                    include_descendants: false,
                },
                RequestId::random(),
                1_800_000_007_000,
            )
            .unwrap_or_else(|error| panic!("synthetic exact grant must create: {error}"));
        vault
            .add_policy_grant(
                owner,
                GrantSpec {
                    policy_id: policy,
                    action: Action::SecretList,
                    resource_kind: ResourceKind::Namespace,
                    resource_id: ObjectId::from_uuid(namespace.as_uuid()),
                    include_descendants: false,
                },
                RequestId::random(),
                1_800_000_007_100,
            )
            .unwrap_or_else(|error| panic!("secret-list grant must create: {error}"));
        vault
            .add_policy_grant(
                owner,
                GrantSpec {
                    policy_id: policy,
                    action: Action::NamespaceList,
                    resource_kind: ResourceKind::Namespace,
                    resource_id: ObjectId::from_uuid(namespace.as_uuid()),
                    include_descendants: false,
                },
                RequestId::random(),
                1_800_000_007_200,
            )
            .unwrap_or_else(|error| panic!("namespace-list grant must create: {error}"));
        vault
            .bind_policy_to_service(
                owner,
                service,
                policy,
                RequestId::random(),
                1_800_000_008_000,
            )
            .unwrap_or_else(|error| panic!("synthetic binding must create: {error}"));
        let populated_rules = vault
            .policy_rules(owner, policy, RequestId::random(), 1_800_000_008_050)
            .unwrap_or_else(|error| panic!("populated policy rules must read: {error}"));
        assert_eq!(populated_rules.grants.len(), 3);
        assert_eq!(populated_rules.bindings.len(), 1);
        assert_eq!(populated_rules.bindings[0].principal_id, service);
        let writer = vault
            .create_service_identity(
                owner,
                &ServiceIdentityMetadata {
                    label: ProtectedString::new(String::from("synthetic writer")),
                    description: None,
                },
                RequestId::random(),
                1_800_000_008_100,
            )
            .unwrap_or_else(|error| panic!("writer identity must create: {error}"));
        let writer_policy = vault
            .create_policy(
                owner,
                &PolicyMetadata {
                    label: ProtectedString::new(String::from("write only")),
                },
                RequestId::random(),
                1_800_000_008_200,
            )
            .unwrap_or_else(|error| panic!("writer policy must create: {error}"));
        vault
            .add_policy_grant(
                owner,
                GrantSpec {
                    policy_id: writer_policy,
                    action: Action::SecretCreate,
                    resource_kind: ResourceKind::Namespace,
                    resource_id: ObjectId::from_uuid(namespace.as_uuid()),
                    include_descendants: false,
                },
                RequestId::random(),
                1_800_000_008_300,
            )
            .unwrap_or_else(|error| panic!("writer grant must create: {error}"));
        vault
            .bind_policy_to_service(
                owner,
                writer,
                writer_policy,
                RequestId::random(),
                1_800_000_008_400,
            )
            .unwrap_or_else(|error| panic!("writer binding must create: {error}"));
        let writer_credential = vault
            .issue_application_credential(
                owner,
                writer,
                None,
                RequestId::random(),
                1_800_000_008_500,
            )
            .unwrap_or_else(|error| panic!("writer credential must issue: {error}"));
        let writer_auth = vault
            .authenticate_application_credential(&writer_credential.plaintext, 1_800_000_008_600)
            .unwrap_or_else(|error| panic!("writer must authenticate: {error}"));
        let writer_vault = vault
            .authorized(
                RequestPrincipal::Service(writer_auth),
                RequestId::random(),
                1_800_000_008_700,
            )
            .unwrap_or_else(|error| panic!("writer must authorize: {error}"));
        let written = writer_vault
            .create_secret(
                namespace,
                &metadata("write-only secret"),
                ProtectedBytes::new(b"write-only-value".to_vec()),
                SecretSchedule::default(),
            )
            .unwrap_or_else(|error| panic!("write-only service must create: {error}"));
        assert!(
            writer_vault
                .reveal_current_secret(written.secret_id)
                .is_err()
        );
        drop(writer_vault);
        let credential = vault
            .issue_application_credential(
                owner,
                service,
                None,
                RequestId::random(),
                1_800_000_009_000,
            )
            .unwrap_or_else(|error| panic!("synthetic credential must issue: {error}"));
        let service_auth = vault
            .authenticate_application_credential(&credential.plaintext, 1_800_000_010_000)
            .unwrap_or_else(|error| panic!("synthetic service must authenticate: {error}"));
        let service_vault = vault
            .authorized(
                RequestPrincipal::Service(service_auth),
                RequestId::random(),
                1_800_000_011_000,
            )
            .unwrap_or_else(|error| panic!("service authorization must succeed: {error}"));

        let revealed = service_vault
            .reveal_current_secret(first.secret_id)
            .unwrap_or_else(|error| panic!("exact grant must reveal: {error}"));
        assert_eq!(revealed.expose(), b"second-value");
        let listed = service_vault
            .list_secrets(namespace, None, 100)
            .unwrap_or_else(|error| panic!("separately granted secret list must work: {error}"));
        assert!(listed.iter().any(|item| item.secret_id == first.secret_id));
        let child_namespaces = service_vault
            .list_namespaces(Some(namespace), None, 100)
            .unwrap_or_else(|error| panic!("separately granted namespace list must work: {error}"));
        assert!(child_namespaces.is_empty());
        assert!(
            service_vault
                .reveal_current_secret(sibling.secret_id)
                .is_err()
        );
        assert!(
            service_vault
                .secret_version_history(first.secret_id, 0, 10)
                .is_err()
        );
        assert!(
            service_vault
                .reveal_secret_version(first.secret_id, 1)
                .is_err()
        );
        drop(service_vault);
        assert!(
            vault
                .authorize(
                    RequestPrincipal::Service(service_auth),
                    Action::PolicyManage,
                    ResourceKind::Secret,
                    ObjectId::from_uuid(first.secret_id.as_uuid()),
                    RequestId::random(),
                    1_800_000_012_000,
                )
                .is_err()
        );
        let inherited_policy = vault
            .create_policy(
                owner,
                &PolicyMetadata {
                    label: ProtectedString::new(String::from("inherited metadata")),
                },
                RequestId::random(),
                1_800_000_013_000,
            )
            .unwrap_or_else(|error| panic!("inherited policy must create: {error}"));
        vault
            .add_policy_grant(
                owner,
                GrantSpec {
                    policy_id: inherited_policy,
                    action: Action::SecretMetadataRead,
                    resource_kind: ResourceKind::Namespace,
                    resource_id: ObjectId::from_uuid(broader_parent.as_uuid()),
                    include_descendants: true,
                },
                RequestId::random(),
                1_800_000_014_000,
            )
            .unwrap_or_else(|error| panic!("inherited grant must create: {error}"));
        vault
            .bind_policy_to_service(
                owner,
                service,
                inherited_policy,
                RequestId::random(),
                1_800_000_015_000,
            )
            .unwrap_or_else(|error| panic!("inherited binding must create: {error}"));
        let delta = vault
            .preview_namespace_move(owner, namespace, Some(broader_parent), 1_800_000_016_000)
            .unwrap_or_else(|error| panic!("move delta must preview: {error}"));
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].principal_id, service);
        assert_eq!(delta[0].action, Action::SecretMetadataRead);
        assert!(
            vault
                .move_namespace(
                    owner,
                    namespace,
                    1,
                    Some(broader_parent),
                    &[],
                    RequestId::random(),
                    1_800_000_017_000,
                )
                .is_err()
        );
        vault
            .move_namespace(
                owner,
                namespace,
                1,
                Some(broader_parent),
                &delta,
                RequestId::random(),
                1_800_000_018_000,
            )
            .unwrap_or_else(|error| panic!("confirmed move must complete: {error}"));
        let service_vault = vault
            .authorized(
                RequestPrincipal::Service(service_auth),
                RequestId::random(),
                1_800_000_018_500,
            )
            .unwrap_or_else(|error| panic!("service reauthorization must succeed: {error}"));
        service_vault
            .read_secret_metadata(sibling.secret_id)
            .unwrap_or_else(|error| panic!("new inherited access must apply: {error}"));
        drop(service_vault);
        vault
            .archive_policy(owner, policy, 1, RequestId::random(), 1_800_000_019_000)
            .unwrap_or_else(|error| panic!("exact policy must archive: {error}"));
        let service_vault = vault
            .authorized(
                RequestPrincipal::Service(service_auth),
                RequestId::random(),
                1_800_000_019_500,
            )
            .unwrap_or_else(|error| panic!("active credential must reauthorize: {error}"));
        assert!(
            service_vault
                .reveal_current_secret(first.secret_id)
                .is_err()
        );
        let audit = vault
            .store
            .audit_records_after(0, 1_000)
            .unwrap_or_else(|error| panic!("synthetic audit must read: {error}"));
        assert!(audit.iter().any(|event| {
            event.action == "secret:value-read"
                && event.credential_kind.as_deref() == Some("application")
                && event.credential_id
                    == Some(ObjectId::from_uuid(service_auth.credential_id().as_uuid()))
                && event.commitment_version == 2
        }));
    }
}

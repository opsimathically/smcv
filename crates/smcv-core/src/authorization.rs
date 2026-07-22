use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{ObjectId, PolicyId};

/// Closed v1 authorization action vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    NamespaceList,
    NamespaceCreate,
    NamespaceUpdate,
    NamespaceDelete,
    SecretList,
    SecretMetadataRead,
    SecretValueRead,
    SecretCreate,
    SecretUpdate,
    SecretArchive,
    SecretRestore,
    SecretHistoryRead,
    SecretVersionRead,
    SecretPurge,
    IdentityRead,
    IdentityManage,
    CredentialIssue,
    CredentialRevoke,
    PolicyRead,
    PolicyManage,
    EffectiveAccessRead,
    AuditRead,
    BackupCreate,
    BackupInspect,
    BackupRestore,
    KeyRotate,
    VaultConfigure,
    VaultLock,
}

impl Action {
    /// Stable audit/API spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NamespaceList => "namespace:list",
            Self::NamespaceCreate => "namespace:create",
            Self::NamespaceUpdate => "namespace:update",
            Self::NamespaceDelete => "namespace:delete",
            Self::SecretList => "secret:list",
            Self::SecretMetadataRead => "secret:metadata-read",
            Self::SecretValueRead => "secret:value-read",
            Self::SecretCreate => "secret:create",
            Self::SecretUpdate => "secret:update",
            Self::SecretArchive => "secret:archive",
            Self::SecretRestore => "secret:restore",
            Self::SecretHistoryRead => "secret:history-read",
            Self::SecretVersionRead => "secret:version-read",
            Self::SecretPurge => "secret:purge",
            Self::IdentityRead => "identity:read",
            Self::IdentityManage => "identity:manage",
            Self::CredentialIssue => "credential:issue",
            Self::CredentialRevoke => "credential:revoke",
            Self::PolicyRead => "policy:read",
            Self::PolicyManage => "policy:manage",
            Self::EffectiveAccessRead => "effective-access:read",
            Self::AuditRead => "audit:read",
            Self::BackupCreate => "backup:create",
            Self::BackupInspect => "backup:inspect",
            Self::BackupRestore => "backup:restore",
            Self::KeyRotate => "key:rotate",
            Self::VaultConfigure => "vault:configure",
            Self::VaultLock => "vault:lock",
        }
    }

    /// Whether a service policy may contain this action.
    #[must_use]
    pub const fn is_service_grantable(self) -> bool {
        matches!(
            self,
            Self::NamespaceList
                | Self::SecretList
                | Self::SecretMetadataRead
                | Self::SecretValueRead
                | Self::SecretCreate
                | Self::SecretUpdate
                | Self::SecretArchive
                | Self::SecretRestore
                | Self::SecretHistoryRead
                | Self::SecretVersionRead
        )
    }

    /// Complete iterable action set for generated authorization matrices.
    pub const ALL: [Self; 28] = [
        Self::NamespaceList,
        Self::NamespaceCreate,
        Self::NamespaceUpdate,
        Self::NamespaceDelete,
        Self::SecretList,
        Self::SecretMetadataRead,
        Self::SecretValueRead,
        Self::SecretCreate,
        Self::SecretUpdate,
        Self::SecretArchive,
        Self::SecretRestore,
        Self::SecretHistoryRead,
        Self::SecretVersionRead,
        Self::SecretPurge,
        Self::IdentityRead,
        Self::IdentityManage,
        Self::CredentialIssue,
        Self::CredentialRevoke,
        Self::PolicyRead,
        Self::PolicyManage,
        Self::EffectiveAccessRead,
        Self::AuditRead,
        Self::BackupCreate,
        Self::BackupInspect,
        Self::BackupRestore,
        Self::KeyRotate,
        Self::VaultConfigure,
        Self::VaultLock,
    ];
}

impl FromStr for Action {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|action| action.as_str() == value)
            .ok_or(())
    }
}

/// Resource classes addressable by v1 service policies.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Namespace,
    Secret,
}

impl ResourceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::Secret => "secret",
        }
    }
}

/// Validated service-policy grant input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantSpec {
    pub policy_id: PolicyId,
    pub action: Action,
    pub resource_kind: ResourceKind,
    pub resource_id: ObjectId,
    pub include_descendants: bool,
}

impl GrantSpec {
    /// Validates the closed service-policy subset.
    #[must_use]
    pub const fn is_valid_for_service(self) -> bool {
        self.action.is_service_grantable()
            && (!self.include_descendants || matches!(self.resource_kind, ResourceKind::Namespace))
    }
}

#[cfg(test)]
mod tests {
    use crate::{Action, GrantSpec, ObjectId, PolicyId, ResourceKind};

    #[test]
    fn owner_only_actions_never_validate_for_service_grants() {
        for action in Action::ALL {
            let grant = GrantSpec {
                policy_id: PolicyId::random(),
                action,
                resource_kind: ResourceKind::Secret,
                resource_id: ObjectId::random(),
                include_descendants: false,
            };
            assert_eq!(grant.is_valid_for_service(), action.is_service_grantable());
        }
    }
}

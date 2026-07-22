use core::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! opaque_id {
    ($name:ident) => {
        #[doc = concat!("Opaque identifier for ", stringify!($name), ".")]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates an identifier from a UUID.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Creates a random version-4 identifier.
            #[must_use]
            pub fn random() -> Self {
                Self(Uuid::new_v4())
            }

            /// Returns the underlying UUID for persistence and protocol adapters.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            /// Returns the stable 16-byte representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

opaque_id!(VaultId);
opaque_id!(InstallationId);
opaque_id!(NamespaceId);
opaque_id!(SecretId);
opaque_id!(PrincipalId);
opaque_id!(RequestId);
opaque_id!(ObjectId);

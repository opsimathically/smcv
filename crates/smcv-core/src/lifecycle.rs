/// Clear operational schedule for one immutable secret version.
///
/// These timestamps describe the upstream credential; they do not claim that
/// SMCV can rotate or revoke that credential in its source system.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecretSchedule {
    /// Time after which the stored upstream credential is expected to expire.
    pub expires_at_unix_ms: Option<i64>,
    /// Time when an owner should replace the upstream credential value.
    pub rotation_due_at_unix_ms: Option<i64>,
}

impl SecretSchedule {
    /// Returns whether all present timestamps are non-negative Unix times.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.expires_at_unix_ms.is_none_or(|value| value >= 0)
            && self.rotation_due_at_unix_ms.is_none_or(|value| value >= 0)
    }
}

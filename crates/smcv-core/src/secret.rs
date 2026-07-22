use core::fmt;

use zeroize::Zeroizing;

/// Owned protected bytes with deliberately redacted formatting.
pub struct ProtectedBytes(Zeroizing<Vec<u8>>);

impl ProtectedBytes {
    /// Takes ownership of protected bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Exposes protected bytes only at an explicit call site.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the protected payload length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when the protected payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ProtectedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedBytes([REDACTED])")
    }
}

/// Owned UTF-8 protected text with deliberately redacted formatting.
pub struct ProtectedString(Zeroizing<String>);

impl ProtectedString {
    /// Takes ownership of protected text.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Exposes protected text only at an explicit call site.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ProtectedString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedString([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtectedBytes, ProtectedString};

    #[test]
    fn debug_output_is_redacted() {
        let bytes = ProtectedBytes::new(b"phase-zero-sentinel".to_vec());
        let text = ProtectedString::new(String::from("phase-zero-sentinel"));

        assert_eq!(format!("{bytes:?}"), "ProtectedBytes([REDACTED])");
        assert_eq!(format!("{text:?}"), "ProtectedString([REDACTED])");
    }
}

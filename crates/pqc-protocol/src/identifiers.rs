//! Protocol identifiers and versioning types.

/// Protocol version identifier.
///
/// The major component changes when wire compatibility is broken. The minor
/// component changes when backward-compatible behavior is added.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// Construct a protocol version.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Return the major version component.
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Return the minor version component.
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// Identifier for a cryptographic policy selected by a protocol.
///
/// The numeric registry and wire encoding will be specified in a later stage.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PolicyId(u16);

impl PolicyId {
    /// Construct a policy identifier.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the numeric policy identifier.
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Opaque identifier for one protocol session.
///
/// This type defines ownership and equality semantics only. Random generation,
/// encoding, and validation rules will be introduced with the wire format.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// Construct a session identifier from its fixed-width representation.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the fixed-width session identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_accessors_preserve_components() {
        let version = ProtocolVersion::new(1, 2);
        assert_eq!(version.major(), 1);
        assert_eq!(version.minor(), 2);
    }

    #[test]
    fn policy_identifier_round_trips() {
        assert_eq!(PolicyId::new(7).value(), 7);
    }

    #[test]
    fn session_identifier_preserves_bytes() {
        let bytes = [0x5a; 16];
        assert_eq!(SessionId::from_bytes(bytes).as_bytes(), &bytes);
    }
}

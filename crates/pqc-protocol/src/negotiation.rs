//! Transport-independent protocol capability negotiation vocabulary.

use crate::CapabilityId;

/// Error produced while validating a capability offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityOfferError {
    /// The offer contains the same capability more than once.
    DuplicateCapability {
        /// Capability identifier that was repeated.
        capability: CapabilityId,
    },
}

/// Result type used while validating capability offers.
pub type CapabilityOfferResult<T> = core::result::Result<T, CapabilityOfferError>;

impl core::fmt::Display for CapabilityOfferError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateCapability { .. } => {
                formatter.write_str("duplicate protocol capability in offer")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CapabilityOfferError {}

/// Ordered, borrowed set of protocol capabilities offered by one peer.
///
/// Capability ordering is significant: lower indices represent stronger
/// advertised preference. An offer may be empty. Duplicate capability
/// identifiers are rejected during construction.
///
/// This type performs no allocation, transport I/O, policy evaluation,
/// session mutation, cryptographic selection, or wire encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityOffer<'a> {
    capabilities: &'a [CapabilityId],
}

impl<'a> CapabilityOffer<'a> {
    /// Validate and construct an ordered capability offer.
    pub fn new(capabilities: &'a [CapabilityId]) -> CapabilityOfferResult<Self> {
        let mut outer = 0;

        while outer < capabilities.len() {
            let capability = capabilities[outer];
            let mut inner = outer + 1;

            while inner < capabilities.len() {
                if capabilities[inner] == capability {
                    return Err(CapabilityOfferError::DuplicateCapability { capability });
                }

                inner += 1;
            }

            outer += 1;
        }

        Ok(Self { capabilities })
    }

    /// Return the ordered capability identifiers.
    pub const fn capabilities(&self) -> &'a [CapabilityId] {
        self.capabilities
    }

    /// Return the number of capabilities in the offer.
    pub const fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Return whether the offer contains no capabilities.
    pub const fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Return whether `capability` appears in the offer.
    pub fn contains(&self, capability: CapabilityId) -> bool {
        self.preference(capability).is_some()
    }

    /// Return the zero-based advertised preference of `capability`.
    ///
    /// Lower indices represent stronger advertised preference.
    pub fn preference(&self, capability: CapabilityId) -> Option<usize> {
        let mut index = 0;

        while index < self.capabilities.len() {
            if self.capabilities[index] == capability {
                return Some(index);
            }

            index += 1;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_preserves_ordered_capabilities() {
        let capabilities = [
            CapabilityId::new(7),
            CapabilityId::new(3),
            CapabilityId::new(11),
        ];

        let offer = CapabilityOffer::new(&capabilities).unwrap();

        assert_eq!(offer.capabilities(), &capabilities);
        assert_eq!(offer.len(), 3);
        assert!(!offer.is_empty());
    }

    #[test]
    fn empty_offer_is_valid() {
        let offer = CapabilityOffer::new(&[]).unwrap();

        assert!(offer.is_empty());
        assert_eq!(offer.len(), 0);
        assert_eq!(offer.capabilities(), &[]);
    }

    #[test]
    fn duplicate_capability_is_rejected() {
        let capabilities = [
            CapabilityId::new(7),
            CapabilityId::new(3),
            CapabilityId::new(7),
        ];

        assert_eq!(
            CapabilityOffer::new(&capabilities),
            Err(CapabilityOfferError::DuplicateCapability {
                capability: CapabilityId::new(7),
            })
        );
    }

    #[test]
    fn contains_reports_membership() {
        let capabilities = [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(30),
        ];
        let offer = CapabilityOffer::new(&capabilities).unwrap();

        assert!(offer.contains(CapabilityId::new(10)));
        assert!(offer.contains(CapabilityId::new(20)));
        assert!(offer.contains(CapabilityId::new(30)));
        assert!(!offer.contains(CapabilityId::new(40)));
    }

    #[test]
    fn preference_reports_zero_based_order() {
        let capabilities = [
            CapabilityId::new(100),
            CapabilityId::new(200),
            CapabilityId::new(300),
        ];
        let offer = CapabilityOffer::new(&capabilities).unwrap();

        assert_eq!(offer.preference(CapabilityId::new(100)), Some(0));
        assert_eq!(offer.preference(CapabilityId::new(200)), Some(1));
        assert_eq!(offer.preference(CapabilityId::new(300)), Some(2));
        assert_eq!(offer.preference(CapabilityId::new(400)), None);
    }

    #[test]
    fn offer_borrows_caller_owned_storage() {
        let capabilities = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];

        let offer = CapabilityOffer::new(&capabilities).unwrap();

        assert!(core::ptr::eq(
            offer.capabilities().as_ptr(),
            capabilities.as_ptr(),
        ));
    }

    #[test]
    fn ordering_is_semantically_preserved() {
        let first = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];
        let second = [
            CapabilityId::new(3),
            CapabilityId::new(2),
            CapabilityId::new(1),
        ];

        let first_offer = CapabilityOffer::new(&first).unwrap();
        let second_offer = CapabilityOffer::new(&second).unwrap();

        assert_ne!(first_offer, second_offer);
        assert_eq!(first_offer.preference(CapabilityId::new(1)), Some(0));
        assert_eq!(second_offer.preference(CapabilityId::new(1)), Some(2));
    }
}

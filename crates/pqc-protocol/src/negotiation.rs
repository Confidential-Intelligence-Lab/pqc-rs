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

/// Select the locally preferred capability also supported by `peer`.
///
/// Local offer ordering defines preference precedence. The first capability
/// present in both validated offers is selected. If the offers have no common
/// capability, this function returns `None`.
///
/// This operation performs no allocation, transport I/O, policy evaluation,
/// session mutation, cryptographic resolution, or wire processing.
pub fn select_preferred_common(
    local: CapabilityOffer<'_>,
    peer: CapabilityOffer<'_>,
) -> Option<CapabilityId> {
    let capabilities = local.capabilities();
    let mut index = 0;

    while index < capabilities.len() {
        let capability = capabilities[index];

        if peer.contains(capability) {
            return Some(capability);
        }

        index += 1;
    }

    None
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    #[test]
    fn same_order_overlap_selects_first_common_capability() {
        let local_ids = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];
        let peer_ids = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();

        assert_eq!(
            select_preferred_common(local, peer),
            Some(CapabilityId::new(1))
        );
    }

    #[test]
    fn local_preference_order_controls_selection() {
        let local_ids = [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(30),
        ];
        let peer_ids = [
            CapabilityId::new(30),
            CapabilityId::new(20),
            CapabilityId::new(10),
        ];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();

        assert_eq!(
            select_preferred_common(local, peer),
            Some(CapabilityId::new(10))
        );
    }

    #[test]
    fn peer_only_capabilities_are_ignored() {
        let local_ids = [CapabilityId::new(2), CapabilityId::new(3)];
        let peer_ids = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();

        assert_eq!(
            select_preferred_common(local, peer),
            Some(CapabilityId::new(2))
        );
    }

    #[test]
    fn single_overlap_is_selected() {
        let local_ids = [
            CapabilityId::new(4),
            CapabilityId::new(5),
            CapabilityId::new(6),
        ];
        let peer_ids = [
            CapabilityId::new(8),
            CapabilityId::new(6),
            CapabilityId::new(9),
        ];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();

        assert_eq!(
            select_preferred_common(local, peer),
            Some(CapabilityId::new(6))
        );
    }

    #[test]
    fn no_overlap_returns_none() {
        let local_ids = [CapabilityId::new(1), CapabilityId::new(2)];
        let peer_ids = [CapabilityId::new(3), CapabilityId::new(4)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();

        assert_eq!(select_preferred_common(local, peer), None);
    }

    #[test]
    fn empty_local_offer_returns_none() {
        let peer_ids = [CapabilityId::new(1), CapabilityId::new(2)];

        let local = CapabilityOffer::new(&[]).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();

        assert_eq!(select_preferred_common(local, peer), None);
    }

    #[test]
    fn empty_peer_offer_returns_none() {
        let local_ids = [CapabilityId::new(1), CapabilityId::new(2)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&[]).unwrap();

        assert_eq!(select_preferred_common(local, peer), None);
    }

    #[test]
    fn selection_is_deterministic() {
        let local_ids = [
            CapabilityId::new(7),
            CapabilityId::new(3),
            CapabilityId::new(11),
        ];
        let peer_ids = [CapabilityId::new(11), CapabilityId::new(3)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();

        let expected = Some(CapabilityId::new(3));

        for _ in 0..16 {
            assert_eq!(select_preferred_common(local, peer), expected);
        }
    }

    #[test]
    fn selected_capability_is_present_in_both_offers() {
        let local_ids = [
            CapabilityId::new(100),
            CapabilityId::new(200),
            CapabilityId::new(300),
        ];
        let peer_ids = [
            CapabilityId::new(900),
            CapabilityId::new(300),
            CapabilityId::new(200),
        ];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();

        let selected = select_preferred_common(local, peer).unwrap();

        assert!(local.contains(selected));
        assert!(peer.contains(selected));
    }

    #[test]
    fn selection_does_not_change_offer_semantics() {
        let local_ids = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];
        let peer_ids = [CapabilityId::new(3), CapabilityId::new(2)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();

        let local_before = local;
        let peer_before = peer;

        assert_eq!(
            select_preferred_common(local, peer),
            Some(CapabilityId::new(2))
        );

        assert_eq!(local, local_before);
        assert_eq!(peer, peer_before);
    }
}

/// Error produced while validating a resolved capability policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityPolicyError {
    /// The resolved policy contains the same capability more than once.
    DuplicateCapability {
        /// Capability identifier that was repeated.
        capability: CapabilityId,
    },
}

/// Result type used while validating resolved capability policies.
pub type CapabilityPolicyResult<T> = core::result::Result<T, CapabilityPolicyError>;

impl core::fmt::Display for CapabilityPolicyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateCapability { .. } => {
                formatter.write_str("duplicate protocol capability in resolved policy")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CapabilityPolicyError {}

/// Resolved local policy constraints for protocol capability selection.
///
/// [`crate::PolicyId`] identifies the externally defined policy. `allowed`
/// contains the capabilities that an external policy-resolution layer has
/// determined are permitted under that policy.
///
/// The allowed list is not a peer advertisement and does not define selection
/// preference. Local [`CapabilityOffer`] ordering remains authoritative for
/// preference among otherwise eligible capabilities.
///
/// This type performs no allocation, policy interpretation, provider
/// resolution, transport I/O, session mutation, cryptographic execution, or
/// wire processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityPolicy<'a> {
    policy_id: crate::PolicyId,
    allowed: &'a [CapabilityId],
}

impl<'a> CapabilityPolicy<'a> {
    /// Validate and construct resolved local capability constraints.
    pub fn new(
        policy_id: crate::PolicyId,
        allowed: &'a [CapabilityId],
    ) -> CapabilityPolicyResult<Self> {
        let mut outer = 0;

        while outer < allowed.len() {
            let capability = allowed[outer];
            let mut inner = outer + 1;

            while inner < allowed.len() {
                if allowed[inner] == capability {
                    return Err(CapabilityPolicyError::DuplicateCapability { capability });
                }

                inner += 1;
            }

            outer += 1;
        }

        Ok(Self { policy_id, allowed })
    }

    /// Return the identifier of the externally defined policy.
    pub const fn policy_id(&self) -> crate::PolicyId {
        self.policy_id
    }

    /// Return the capabilities permitted by the resolved policy.
    pub const fn allowed(&self) -> &'a [CapabilityId] {
        self.allowed
    }

    /// Return the number of capabilities permitted by the policy.
    pub const fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Return whether the resolved policy permits no capabilities.
    pub const fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Return whether the resolved policy permits `capability`.
    pub fn permits(&self, capability: CapabilityId) -> bool {
        let mut index = 0;

        while index < self.allowed.len() {
            if self.allowed[index] == capability {
                return true;
            }

            index += 1;
        }

        false
    }
}

/// Select the locally preferred capability supported by the peer and policy.
///
/// Local offer ordering defines selection preference. The resolver walks the
/// local offer from strongest to weakest and selects the first capability that
/// is both present in `peer` and permitted by `policy`.
///
/// The order of the policy allow-list does not affect preference. If no
/// capability satisfies all three constraints, this function returns `None`.
///
/// This operation does not interpret [`crate::PolicyId`] or perform provider
/// resolution, transport I/O, session mutation, cryptographic execution, or
/// wire processing.
pub fn select_policy_permitted_common(
    local: CapabilityOffer<'_>,
    peer: CapabilityOffer<'_>,
    policy: CapabilityPolicy<'_>,
) -> Option<CapabilityId> {
    let capabilities = local.capabilities();
    let mut index = 0;

    while index < capabilities.len() {
        let capability = capabilities[index];

        if peer.contains(capability) && policy.permits(capability) {
            return Some(capability);
        }

        index += 1;
    }

    None
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::PolicyId;

    #[test]
    fn policy_preserves_identifier_and_allowed_capabilities() {
        let allowed = [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(30),
        ];

        let policy = CapabilityPolicy::new(PolicyId::new(7), &allowed).unwrap();

        assert_eq!(policy.policy_id(), PolicyId::new(7));
        assert_eq!(policy.allowed(), &allowed);
        assert_eq!(policy.len(), 3);
        assert!(!policy.is_empty());
    }

    #[test]
    fn empty_policy_is_structurally_valid() {
        let policy = CapabilityPolicy::new(PolicyId::new(7), &[]).unwrap();

        assert_eq!(policy.policy_id(), PolicyId::new(7));
        assert!(policy.allowed().is_empty());
        assert_eq!(policy.len(), 0);
        assert!(policy.is_empty());
    }

    #[test]
    fn duplicate_policy_capability_is_rejected() {
        let allowed = [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(10),
        ];

        assert_eq!(
            CapabilityPolicy::new(PolicyId::new(7), &allowed),
            Err(CapabilityPolicyError::DuplicateCapability {
                capability: CapabilityId::new(10),
            })
        );
    }

    #[test]
    fn policy_reports_capability_permission() {
        let allowed = [CapabilityId::new(10), CapabilityId::new(20)];
        let policy = CapabilityPolicy::new(PolicyId::new(7), &allowed).unwrap();

        assert!(policy.permits(CapabilityId::new(10)));
        assert!(policy.permits(CapabilityId::new(20)));
        assert!(!policy.permits(CapabilityId::new(30)));
    }

    #[test]
    fn policy_can_exclude_first_mutually_supported_capability() {
        let local_ids = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];
        let peer_ids = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];
        let allowed = [CapabilityId::new(2), CapabilityId::new(3)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(1), &allowed).unwrap();

        assert_eq!(
            select_policy_permitted_common(local, peer, policy),
            Some(CapabilityId::new(2))
        );
    }

    #[test]
    fn local_preference_remains_authoritative_after_policy_filtering() {
        let local_ids = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];
        let peer_ids = [
            CapabilityId::new(3),
            CapabilityId::new(2),
            CapabilityId::new(1),
        ];
        let allowed = [CapabilityId::new(3), CapabilityId::new(1)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(2), &allowed).unwrap();

        assert_eq!(
            select_policy_permitted_common(local, peer, policy),
            Some(CapabilityId::new(1))
        );
    }

    #[test]
    fn policy_allow_list_order_does_not_change_selection() {
        let local_ids = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];
        let peer_ids = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];
        let allowed_a = [CapabilityId::new(3), CapabilityId::new(2)];
        let allowed_b = [CapabilityId::new(2), CapabilityId::new(3)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy_a = CapabilityPolicy::new(PolicyId::new(3), &allowed_a).unwrap();
        let policy_b = CapabilityPolicy::new(PolicyId::new(3), &allowed_b).unwrap();

        assert_eq!(
            select_policy_permitted_common(local, peer, policy_a),
            Some(CapabilityId::new(2))
        );
        assert_eq!(
            select_policy_permitted_common(local, peer, policy_b),
            Some(CapabilityId::new(2))
        );
    }

    #[test]
    fn no_policy_permitted_common_capability_returns_none() {
        let local_ids = [CapabilityId::new(1), CapabilityId::new(2)];
        let peer_ids = [CapabilityId::new(1), CapabilityId::new(2)];
        let allowed = [CapabilityId::new(3), CapabilityId::new(4)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(4), &allowed).unwrap();

        assert_eq!(select_policy_permitted_common(local, peer, policy), None);
    }

    #[test]
    fn empty_policy_selects_nothing() {
        let local_ids = [CapabilityId::new(1), CapabilityId::new(2)];
        let peer_ids = [CapabilityId::new(1), CapabilityId::new(2)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(5), &[]).unwrap();

        assert_eq!(select_policy_permitted_common(local, peer, policy), None);
    }

    #[test]
    fn selected_capability_satisfies_all_three_constraints() {
        let local_ids = [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(30),
        ];
        let peer_ids = [
            CapabilityId::new(40),
            CapabilityId::new(30),
            CapabilityId::new(20),
        ];
        let allowed = [CapabilityId::new(50), CapabilityId::new(30)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(6), &allowed).unwrap();

        let selected = select_policy_permitted_common(local, peer, policy).unwrap();

        assert!(local.contains(selected));
        assert!(peer.contains(selected));
        assert!(policy.permits(selected));
        assert_eq!(selected, CapabilityId::new(30));
    }

    #[test]
    fn policy_constrained_selection_is_deterministic() {
        let local_ids = [
            CapabilityId::new(7),
            CapabilityId::new(3),
            CapabilityId::new(11),
        ];
        let peer_ids = [
            CapabilityId::new(11),
            CapabilityId::new(3),
            CapabilityId::new(7),
        ];
        let allowed = [CapabilityId::new(11), CapabilityId::new(3)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(8), &allowed).unwrap();

        let expected = Some(CapabilityId::new(3));

        for _ in 0..16 {
            assert_eq!(
                select_policy_permitted_common(local, peer, policy),
                expected
            );
        }
    }
}

/// Capability and policy selected by successful capability negotiation.
///
/// This value records the capability selected from the local and peer offers
/// together with the policy under which that selection was permitted. It is
/// produced by [`negotiate_policy_permitted_common`] rather than by an
/// unrestricted public constructor so that callers cannot construct a
/// negotiated result without performing the corresponding selection.
///
/// The result contains only negotiation metadata. It does not mutate or own a
/// protocol session, transport, cryptographic context, or provider state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NegotiatedCapability {
    policy_id: crate::PolicyId,
    capability: CapabilityId,
}

impl NegotiatedCapability {
    /// Return the policy under which the capability was selected.
    pub const fn policy_id(self) -> crate::PolicyId {
        self.policy_id
    }

    /// Return the selected capability.
    pub const fn capability(self) -> CapabilityId {
        self.capability
    }
}

/// Select and bind the preferred mutually supported capability permitted by
/// `policy`.
///
/// Selection preserves the semantics of
/// [`select_policy_permitted_common`]: local offer order determines
/// preference, the selected capability must also occur in the peer offer, and
/// the policy must permit it.
///
/// On success, the selected capability is bound to the policy identifier in a
/// [`NegotiatedCapability`]. If no capability satisfies all three conditions,
/// this function returns `None`.
///
/// This operation performs no transport I/O and does not mutate protocol
/// session state.
pub fn negotiate_policy_permitted_common(
    local: CapabilityOffer<'_>,
    peer: CapabilityOffer<'_>,
    policy: CapabilityPolicy<'_>,
) -> Option<NegotiatedCapability> {
    let policy_id = policy.policy_id();
    let capability = select_policy_permitted_common(local, peer, policy)?;

    Some(NegotiatedCapability {
        policy_id,
        capability,
    })
}

#[cfg(test)]
mod negotiated_capability_tests {
    use super::*;
    use crate::PolicyId;

    #[test]
    fn negotiation_binds_selected_capability_and_policy() {
        let local_ids = [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(30),
        ];
        let peer_ids = [CapabilityId::new(30), CapabilityId::new(20)];
        let allowed = [CapabilityId::new(20), CapabilityId::new(30)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(7), &allowed).unwrap();

        let negotiated = negotiate_policy_permitted_common(local, peer, policy).unwrap();

        assert_eq!(negotiated.policy_id(), PolicyId::new(7));
        assert_eq!(negotiated.capability(), CapabilityId::new(20));
    }

    #[test]
    fn negotiation_preserves_local_preference() {
        let local_ids = [
            CapabilityId::new(3),
            CapabilityId::new(2),
            CapabilityId::new(1),
        ];
        let peer_ids = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];
        let allowed = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
        ];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(8), &allowed).unwrap();

        let negotiated = negotiate_policy_permitted_common(local, peer, policy).unwrap();

        assert_eq!(negotiated.capability(), CapabilityId::new(3));
    }

    #[test]
    fn negotiation_rejects_common_capability_forbidden_by_policy() {
        let local_ids = [CapabilityId::new(1), CapabilityId::new(2)];
        let peer_ids = [CapabilityId::new(1), CapabilityId::new(2)];
        let allowed = [CapabilityId::new(9)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(9), &allowed).unwrap();

        assert_eq!(negotiate_policy_permitted_common(local, peer, policy), None);
    }

    #[test]
    fn negotiation_rejects_when_offers_have_no_common_capability() {
        let local_ids = [CapabilityId::new(1), CapabilityId::new(2)];
        let peer_ids = [CapabilityId::new(3), CapabilityId::new(4)];
        let allowed = [
            CapabilityId::new(1),
            CapabilityId::new(2),
            CapabilityId::new(3),
            CapabilityId::new(4),
        ];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(10), &allowed).unwrap();

        assert_eq!(negotiate_policy_permitted_common(local, peer, policy), None);
    }

    #[test]
    fn negotiation_result_is_copyable_value_metadata() {
        let local_ids = [CapabilityId::new(42)];
        let peer_ids = [CapabilityId::new(42)];
        let allowed = [CapabilityId::new(42)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(11), &allowed).unwrap();

        let negotiated = negotiate_policy_permitted_common(local, peer, policy).unwrap();
        let copied = negotiated;

        assert_eq!(copied, negotiated);
        assert_eq!(copied.policy_id(), PolicyId::new(11));
        assert_eq!(copied.capability(), CapabilityId::new(42));
    }
}

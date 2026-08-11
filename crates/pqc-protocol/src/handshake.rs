//! Canonical capability-handshake message vocabulary and payload codecs.

use crate::{
    CapabilityId, CapabilityOffer, MessageId, ProtocolDecode, ProtocolEncode, ProtocolError,
    ProtocolResult,
};

/// Message identifier for a client capability offer.
pub const CAPABILITY_OFFER_MESSAGE_ID: MessageId = MessageId::new(0x0001);

/// Message identifier for a server capability selection.
pub const CAPABILITY_SELECTION_MESSAGE_ID: MessageId = MessageId::new(0x0002);

/// Message identifier for a server capability rejection.
pub const CAPABILITY_REJECTION_MESSAGE_ID: MessageId = MessageId::new(0x0003);

const CAPABILITY_FIELD_LEN: usize = 2;
const OFFER_COUNT_LEN: usize = 2;
const SELECTION_PAYLOAD_LEN: usize = 2;
const REJECTION_PAYLOAD_LEN: usize = 2;
const MAX_OFFER_CAPABILITIES: usize = u16::MAX as usize;

/// Canonically encodable capability-offer handshake payload.
///
/// The payload borrows an already validated [`CapabilityOffer`]. Its wire
/// representation is a big-endian 16-bit capability count followed by that
/// many big-endian 16-bit [`CapabilityId`] values in advertised preference
/// order.
///
/// This type performs no allocation and does not own capability storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityOfferPayload<'a> {
    offer: CapabilityOffer<'a>,
}

impl<'a> CapabilityOfferPayload<'a> {
    /// Construct an encodable capability-offer payload.
    ///
    /// The canonical wire count is 16 bits, so offers containing more than
    /// `u16::MAX` capabilities cannot be represented.
    pub fn new(offer: CapabilityOffer<'a>) -> ProtocolResult<Self> {
        if offer.len() > MAX_OFFER_CAPABILITIES {
            return Err(ProtocolError::InvalidEncoding);
        }

        Ok(Self { offer })
    }

    /// Return the underlying validated semantic capability offer.
    pub const fn offer(&self) -> CapabilityOffer<'a> {
        self.offer
    }

    /// Return the number of capabilities carried by the payload.
    pub const fn len(&self) -> usize {
        self.offer.len()
    }

    /// Return whether the payload carries no capabilities.
    pub const fn is_empty(&self) -> bool {
        self.offer.is_empty()
    }
}

impl ProtocolEncode for CapabilityOfferPayload<'_> {
    fn encoded_len(&self) -> usize {
        OFFER_COUNT_LEN + self.offer.len() * CAPABILITY_FIELD_LEN
    }

    fn encode_into(&self, output: &mut [u8]) -> ProtocolResult<usize> {
        let required = self.encoded_len();

        if output.len() < required {
            return Err(ProtocolError::BufferTooSmall {
                required,
                available: output.len(),
            });
        }

        write_u16(output, 0, self.offer.len() as u16);

        let mut index = 0;

        while index < self.offer.len() {
            let capability = self.offer.capabilities()[index];
            let offset = OFFER_COUNT_LEN + index * CAPABILITY_FIELD_LEN;

            write_u16(output, offset, capability.value());
            index += 1;
        }

        Ok(required)
    }
}

/// Borrowed validated view of a decoded capability-offer payload.
///
/// The view borrows the canonical capability bytes directly from the input.
/// Capabilities are decoded on demand, avoiding allocation and representation
/// casts. Construction validates the encoded count and rejects duplicates.
///
/// Because the generic [`ProtocolDecode`] trait does not associate the
/// returned value's lifetime with its input, this borrowed type exposes
/// lifetime-aware inherent decoding methods instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedCapabilityOffer<'a> {
    encoded_capabilities: &'a [u8],
}

impl<'a> DecodedCapabilityOffer<'a> {
    /// Decode one canonical capability offer from the beginning of `input`.
    ///
    /// Any bytes after the encoded offer remain unconsumed.
    pub fn decode_prefix(input: &'a [u8]) -> ProtocolResult<(Self, usize)> {
        if input.len() < OFFER_COUNT_LEN {
            return Err(ProtocolError::UnexpectedEnd);
        }

        let count = read_u16(input, 0) as usize;
        let capability_bytes = count
            .checked_mul(CAPABILITY_FIELD_LEN)
            .ok_or(ProtocolError::InvalidEncoding)?;
        let required = OFFER_COUNT_LEN
            .checked_add(capability_bytes)
            .ok_or(ProtocolError::InvalidEncoding)?;

        if input.len() < required {
            return Err(ProtocolError::UnexpectedEnd);
        }

        let encoded_capabilities = &input[OFFER_COUNT_LEN..required];
        validate_no_duplicate_capabilities(encoded_capabilities, count)?;

        Ok((
            Self {
                encoded_capabilities,
            },
            required,
        ))
    }

    /// Decode exactly one capability offer and reject trailing bytes.
    pub fn decode_exact(input: &'a [u8]) -> ProtocolResult<Self> {
        let (offer, consumed) = Self::decode_prefix(input)?;

        if consumed != input.len() {
            return Err(ProtocolError::TrailingData);
        }

        Ok(offer)
    }

    /// Return the number of decoded capabilities.
    pub const fn len(&self) -> usize {
        self.encoded_capabilities.len() / CAPABILITY_FIELD_LEN
    }

    /// Return whether the decoded offer contains no capabilities.
    pub const fn is_empty(&self) -> bool {
        self.encoded_capabilities.is_empty()
    }

    /// Return the capability at `index`, if present.
    pub fn capability(&self, index: usize) -> Option<CapabilityId> {
        if index >= self.len() {
            return None;
        }

        let offset = index * CAPABILITY_FIELD_LEN;

        Some(CapabilityId::new(read_u16(
            self.encoded_capabilities,
            offset,
        )))
    }

    /// Return whether the decoded offer contains `capability`.
    pub fn contains(&self, capability: CapabilityId) -> bool {
        let mut index = 0;

        while index < self.len() {
            if self.capability(index) == Some(capability) {
                return true;
            }

            index += 1;
        }

        false
    }
}

/// Capability selected by a server during capability negotiation.
///
/// The canonical encoding is exactly one big-endian 16-bit capability
/// identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CapabilitySelectionPayload {
    capability: CapabilityId,
}

impl CapabilitySelectionPayload {
    /// Construct a capability-selection payload.
    pub const fn new(capability: CapabilityId) -> Self {
        Self { capability }
    }

    /// Return the selected capability.
    pub const fn capability(self) -> CapabilityId {
        self.capability
    }
}

impl ProtocolEncode for CapabilitySelectionPayload {
    fn encoded_len(&self) -> usize {
        SELECTION_PAYLOAD_LEN
    }

    fn encode_into(&self, output: &mut [u8]) -> ProtocolResult<usize> {
        if output.len() < SELECTION_PAYLOAD_LEN {
            return Err(ProtocolError::BufferTooSmall {
                required: SELECTION_PAYLOAD_LEN,
                available: output.len(),
            });
        }

        write_u16(output, 0, self.capability.value());

        Ok(SELECTION_PAYLOAD_LEN)
    }
}

impl ProtocolDecode for CapabilitySelectionPayload {
    fn decode_prefix(input: &[u8]) -> ProtocolResult<(Self, usize)> {
        if input.len() < SELECTION_PAYLOAD_LEN {
            return Err(ProtocolError::UnexpectedEnd);
        }

        Ok((
            Self::new(CapabilityId::new(read_u16(input, 0))),
            SELECTION_PAYLOAD_LEN,
        ))
    }
}

/// Reason a capability negotiation was rejected.
///
/// Rejection reasons describe negotiation failure only. Malformed wire input
/// remains a decoding error and is not converted into a rejection payload.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapabilityRejectionReason {
    /// The peers have no mutually supported capability.
    NoCommonCapability = 0x0001,
    /// Local policy permits no otherwise mutually supported capability.
    PolicyRejected = 0x0002,
}

impl CapabilityRejectionReason {
    /// Return the canonical wire value.
    pub const fn value(self) -> u16 {
        self as u16
    }

    fn from_value(value: u16) -> ProtocolResult<Self> {
        match value {
            0x0001 => Ok(Self::NoCommonCapability),
            0x0002 => Ok(Self::PolicyRejected),
            _ => Err(ProtocolError::InvalidEncoding),
        }
    }
}

/// Capability-negotiation rejection handshake payload.
///
/// The canonical encoding is exactly one big-endian 16-bit rejection reason.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityRejectionPayload {
    reason: CapabilityRejectionReason,
}

impl CapabilityRejectionPayload {
    /// Construct a capability-rejection payload.
    pub const fn new(reason: CapabilityRejectionReason) -> Self {
        Self { reason }
    }

    /// Return the rejection reason.
    pub const fn reason(self) -> CapabilityRejectionReason {
        self.reason
    }
}

impl ProtocolEncode for CapabilityRejectionPayload {
    fn encoded_len(&self) -> usize {
        REJECTION_PAYLOAD_LEN
    }

    fn encode_into(&self, output: &mut [u8]) -> ProtocolResult<usize> {
        if output.len() < REJECTION_PAYLOAD_LEN {
            return Err(ProtocolError::BufferTooSmall {
                required: REJECTION_PAYLOAD_LEN,
                available: output.len(),
            });
        }

        write_u16(output, 0, self.reason.value());

        Ok(REJECTION_PAYLOAD_LEN)
    }
}

impl ProtocolDecode for CapabilityRejectionPayload {
    fn decode_prefix(input: &[u8]) -> ProtocolResult<(Self, usize)> {
        if input.len() < REJECTION_PAYLOAD_LEN {
            return Err(ProtocolError::UnexpectedEnd);
        }

        let reason = CapabilityRejectionReason::from_value(read_u16(input, 0))?;

        Ok((Self::new(reason), REJECTION_PAYLOAD_LEN))
    }
}

fn validate_no_duplicate_capabilities(encoded: &[u8], count: usize) -> ProtocolResult<()> {
    let mut outer = 0;

    while outer < count {
        let outer_value = read_u16(encoded, outer * CAPABILITY_FIELD_LEN);
        let mut inner = outer + 1;

        while inner < count {
            let inner_value = read_u16(encoded, inner * CAPABILITY_FIELD_LEN);

            if outer_value == inner_value {
                return Err(ProtocolError::InvalidEncoding);
            }

            inner += 1;
        }

        outer += 1;
    }

    Ok(())
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_message_ids_are_stable() {
        assert_eq!(CAPABILITY_OFFER_MESSAGE_ID.value(), 0x0001);
        assert_eq!(CAPABILITY_SELECTION_MESSAGE_ID.value(), 0x0002);
        assert_eq!(CAPABILITY_REJECTION_MESSAGE_ID.value(), 0x0003);
    }

    #[test]
    fn offer_encoding_is_canonical_big_endian() {
        let capabilities = [
            CapabilityId::new(0x0102),
            CapabilityId::new(0x0304),
            CapabilityId::new(0xa0b0),
        ];
        let offer = CapabilityOffer::new(&capabilities).unwrap();
        let payload = CapabilityOfferPayload::new(offer).unwrap();
        let mut output = [0_u8; 8];

        let written = payload.encode_into(&mut output).unwrap();

        assert_eq!(written, 8);
        assert_eq!(output, [0x00, 0x03, 0x01, 0x02, 0x03, 0x04, 0xa0, 0xb0]);
    }

    #[test]
    fn empty_offer_has_canonical_zero_count() {
        let offer = CapabilityOffer::new(&[]).unwrap();
        let payload = CapabilityOfferPayload::new(offer).unwrap();
        let mut output = [0xff_u8; 2];

        let written = payload.encode_into(&mut output).unwrap();

        assert_eq!(written, 2);
        assert_eq!(output, [0x00, 0x00]);
        assert!(payload.is_empty());
    }

    #[test]
    fn offer_encoding_rejects_short_output() {
        let capabilities = [CapabilityId::new(1), CapabilityId::new(2)];
        let offer = CapabilityOffer::new(&capabilities).unwrap();
        let payload = CapabilityOfferPayload::new(offer).unwrap();
        let mut output = [0_u8; 5];

        assert_eq!(
            payload.encode_into(&mut output),
            Err(ProtocolError::BufferTooSmall {
                required: 6,
                available: 5,
            })
        );
    }

    #[test]
    fn decoded_offer_preserves_order() {
        let input = [0x00, 0x03, 0x00, 0x07, 0x00, 0x03, 0x00, 0x0b];

        let offer = DecodedCapabilityOffer::decode_exact(&input).unwrap();

        assert_eq!(offer.len(), 3);
        assert_eq!(offer.capability(0), Some(CapabilityId::new(7)));
        assert_eq!(offer.capability(1), Some(CapabilityId::new(3)));
        assert_eq!(offer.capability(2), Some(CapabilityId::new(11)));
        assert_eq!(offer.capability(3), None);
    }

    #[test]
    fn decoded_offer_reports_membership() {
        let input = [0x00, 0x02, 0x00, 0x10, 0x00, 0x20];

        let offer = DecodedCapabilityOffer::decode_exact(&input).unwrap();

        assert!(offer.contains(CapabilityId::new(0x10)));
        assert!(offer.contains(CapabilityId::new(0x20)));
        assert!(!offer.contains(CapabilityId::new(0x30)));
    }

    #[test]
    fn decoded_empty_offer_is_valid() {
        let offer = DecodedCapabilityOffer::decode_exact(&[0x00, 0x00]).unwrap();

        assert!(offer.is_empty());
        assert_eq!(offer.len(), 0);
        assert_eq!(offer.capability(0), None);
    }

    #[test]
    fn offer_prefix_decoding_reports_consumption() {
        let input = [0x00, 0x01, 0x12, 0x34, 0xaa, 0xbb];

        let (offer, consumed) = DecodedCapabilityOffer::decode_prefix(&input).unwrap();

        assert_eq!(consumed, 4);
        assert_eq!(offer.capability(0), Some(CapabilityId::new(0x1234)));
    }

    #[test]
    fn offer_exact_decoding_rejects_trailing_bytes() {
        let input = [0x00, 0x01, 0x12, 0x34, 0xaa];

        assert_eq!(
            DecodedCapabilityOffer::decode_exact(&input),
            Err(ProtocolError::TrailingData)
        );
    }

    #[test]
    fn offer_decoding_rejects_truncated_count() {
        assert_eq!(
            DecodedCapabilityOffer::decode_exact(&[0x00]),
            Err(ProtocolError::UnexpectedEnd)
        );
    }

    #[test]
    fn offer_decoding_rejects_truncated_capabilities() {
        let input = [0x00, 0x02, 0x00, 0x01];

        assert_eq!(
            DecodedCapabilityOffer::decode_exact(&input),
            Err(ProtocolError::UnexpectedEnd)
        );
    }

    #[test]
    fn offer_decoding_rejects_duplicate_capabilities() {
        let input = [0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01];

        assert_eq!(
            DecodedCapabilityOffer::decode_exact(&input),
            Err(ProtocolError::InvalidEncoding)
        );
    }

    #[test]
    fn offer_decode_borrows_input_capability_bytes() {
        let input = [0x00, 0x02, 0x00, 0x01, 0x00, 0x02];

        let offer = DecodedCapabilityOffer::decode_exact(&input).unwrap();

        assert_eq!(
            offer.encoded_capabilities.as_ptr(),
            input[OFFER_COUNT_LEN..].as_ptr()
        );
    }

    #[test]
    fn selection_payload_round_trips() {
        let payload = CapabilitySelectionPayload::new(CapabilityId::new(0x1234));
        let mut encoded = [0_u8; 2];

        assert_eq!(payload.encode_into(&mut encoded).unwrap(), 2);
        assert_eq!(encoded, [0x12, 0x34]);
        assert_eq!(
            CapabilitySelectionPayload::decode_exact(&encoded).unwrap(),
            payload
        );
    }

    #[test]
    fn selection_prefix_decoding_reports_consumption() {
        let input = [0x12, 0x34, 0xaa];

        let (payload, consumed) = CapabilitySelectionPayload::decode_prefix(&input).unwrap();

        assert_eq!(consumed, 2);
        assert_eq!(payload.capability(), CapabilityId::new(0x1234));
    }

    #[test]
    fn selection_decoding_rejects_truncation_and_trailing_data() {
        assert_eq!(
            CapabilitySelectionPayload::decode_exact(&[0x12]),
            Err(ProtocolError::UnexpectedEnd)
        );

        assert_eq!(
            CapabilitySelectionPayload::decode_exact(&[0x12, 0x34, 0x56]),
            Err(ProtocolError::TrailingData)
        );
    }

    #[test]
    fn selection_encoding_rejects_short_output() {
        let payload = CapabilitySelectionPayload::new(CapabilityId::new(7));
        let mut output = [0_u8; 1];

        assert_eq!(
            payload.encode_into(&mut output),
            Err(ProtocolError::BufferTooSmall {
                required: 2,
                available: 1,
            })
        );
    }

    #[test]
    fn rejection_payload_round_trips() {
        for reason in [
            CapabilityRejectionReason::NoCommonCapability,
            CapabilityRejectionReason::PolicyRejected,
        ] {
            let payload = CapabilityRejectionPayload::new(reason);
            let mut encoded = [0_u8; 2];

            assert_eq!(payload.encode_into(&mut encoded).unwrap(), 2);
            assert_eq!(
                CapabilityRejectionPayload::decode_exact(&encoded).unwrap(),
                payload
            );
        }
    }

    #[test]
    fn rejection_encoding_is_canonical_big_endian() {
        let payload = CapabilityRejectionPayload::new(CapabilityRejectionReason::PolicyRejected);
        let mut encoded = [0_u8; 2];

        payload.encode_into(&mut encoded).unwrap();

        assert_eq!(encoded, [0x00, 0x02]);
    }

    #[test]
    fn rejection_decoding_rejects_unknown_reason() {
        assert_eq!(
            CapabilityRejectionPayload::decode_exact(&[0xff, 0xff]),
            Err(ProtocolError::InvalidEncoding)
        );
    }

    #[test]
    fn rejection_decoding_rejects_truncation_and_trailing_data() {
        assert_eq!(
            CapabilityRejectionPayload::decode_exact(&[0x00]),
            Err(ProtocolError::UnexpectedEnd)
        );

        assert_eq!(
            CapabilityRejectionPayload::decode_exact(&[0x00, 0x01, 0x00]),
            Err(ProtocolError::TrailingData)
        );
    }

    #[test]
    fn rejection_encoding_rejects_short_output() {
        let payload =
            CapabilityRejectionPayload::new(CapabilityRejectionReason::NoCommonCapability);
        let mut output = [0_u8; 1];

        assert_eq!(
            payload.encode_into(&mut output),
            Err(ProtocolError::BufferTooSmall {
                required: 2,
                available: 1,
            })
        );
    }
}

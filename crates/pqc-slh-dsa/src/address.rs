//! FIPS 205 address representation and domain-separation types.

use crate::SlhDsaHashFamily;

/// Length in bytes of a full FIPS 205 address.
pub const ADDRESS_BYTES: usize = 32;

/// Length in bytes of the compressed address used by SHA2 parameter sets.
pub const COMPRESSED_ADDRESS_BYTES: usize = 22;

/// Domain-separation type encoded in an SLH-DSA address.
///
/// The numeric values are assigned by FIPS 205.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AddressType {
    /// WOTS+ hash-chain address.
    WotsHash = 0,
    /// WOTS+ public-key compression address.
    WotsPublicKey = 1,
    /// XMSS tree address.
    Tree = 2,
    /// FORS tree address.
    ForsTree = 3,
    /// FORS roots-compression address.
    ForsRoots = 4,
    /// WOTS+ secret-key pseudorandom-function address.
    WotsPrf = 5,
    /// FORS secret-key pseudorandom-function address.
    ForsPrf = 6,
}

/// Encoded address selected for a parameter-set hash family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodedAddress {
    /// Complete 32-byte address used by SHAKE parameter sets.
    Full([u8; ADDRESS_BYTES]),
    /// Compressed 22-byte address used by SHA2 parameter sets.
    Compressed([u8; COMPRESSED_ADDRESS_BYTES]),
}

impl EncodedAddress {
    /// Borrow the encoded address bytes.
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Full(bytes) => bytes,
            Self::Compressed(bytes) => bytes,
        }
    }
}

/// Mutable FIPS 205 address.
///
/// Integer fields are encoded in big-endian order. The final three words have
/// meanings determined by [`AddressType`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Address {
    bytes: [u8; ADDRESS_BYTES],
}

impl Address {
    const LAYER_RANGE: core::ops::Range<usize> = 0..4;
    const TREE_RANGE: core::ops::Range<usize> = 4..16;
    const TYPE_RANGE: core::ops::Range<usize> = 16..20;
    const WORD1_RANGE: core::ops::Range<usize> = 20..24;
    const WORD2_RANGE: core::ops::Range<usize> = 24..28;
    const WORD3_RANGE: core::ops::Range<usize> = 28..32;

    /// Construct an all-zero address.
    pub const fn new() -> Self {
        Self {
            bytes: [0_u8; ADDRESS_BYTES],
        }
    }

    /// Borrow the complete 32-byte address.
    pub const fn as_bytes(&self) -> &[u8; ADDRESS_BYTES] {
        &self.bytes
    }

    /// Set the layer address.
    pub fn set_layer_address(&mut self, layer: u32) {
        self.bytes[Self::LAYER_RANGE].copy_from_slice(&layer.to_be_bytes());
    }

    /// Set the tree address.
    ///
    /// All FIPS 205 parameter sets require at most 64 significant tree-address
    /// bits. The leading four bytes of the 12-byte field remain zero.
    pub fn set_tree_address(&mut self, tree: u64) {
        self.bytes[Self::TREE_RANGE].fill(0);
        self.bytes[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// Set the domain-separation type and clear the final 12 bytes.
    ///
    /// FIPS 205 requires the type-dependent words to be reset whenever the
    /// address type changes.
    pub fn set_type_and_clear(&mut self, address_type: AddressType) {
        self.bytes[Self::TYPE_RANGE].copy_from_slice(&(address_type as u32).to_be_bytes());
        self.bytes[Self::WORD1_RANGE].fill(0);
        self.bytes[Self::WORD2_RANGE].fill(0);
        self.bytes[Self::WORD3_RANGE].fill(0);
    }

    /// Set the key-pair address.
    pub fn set_key_pair_address(&mut self, key_pair: u32) {
        self.set_word1(key_pair);
    }

    /// Set the WOTS+ chain address.
    pub fn set_chain_address(&mut self, chain: u32) {
        self.set_word2(chain);
    }

    /// Set the WOTS+ hash-step address.
    pub fn set_hash_address(&mut self, hash: u32) {
        self.set_word3(hash);
    }

    /// Set the XMSS or FORS tree height.
    pub fn set_tree_height(&mut self, height: u32) {
        self.set_word2(height);
    }

    /// Set the XMSS or FORS tree index.
    pub fn set_tree_index(&mut self, index: u32) {
        self.set_word3(index);
    }

    /// Return the key-pair address.
    pub fn key_pair_address(&self) -> u32 {
        self.word1()
    }

    /// Return the tree index.
    pub fn tree_index(&self) -> u32 {
        self.word3()
    }

    /// Encode the address for the selected hash-function family.
    pub fn encode_for(&self, hash_family: SlhDsaHashFamily) -> EncodedAddress {
        match hash_family {
            SlhDsaHashFamily::Sha2 => EncodedAddress::Compressed(self.compressed()),
            SlhDsaHashFamily::Shake => EncodedAddress::Full(self.bytes),
        }
    }

    /// Return the FIPS 205 compressed address used by SHA2 parameter sets.
    pub fn compressed(&self) -> [u8; COMPRESSED_ADDRESS_BYTES] {
        let mut compressed = [0_u8; COMPRESSED_ADDRESS_BYTES];

        compressed[0] = self.bytes[3];
        compressed[1..9].copy_from_slice(&self.bytes[8..16]);
        compressed[9] = self.bytes[19];
        compressed[10..22].copy_from_slice(&self.bytes[20..32]);

        compressed
    }

    fn set_word1(&mut self, value: u32) {
        self.bytes[Self::WORD1_RANGE].copy_from_slice(&value.to_be_bytes());
    }

    fn set_word2(&mut self, value: u32) {
        self.bytes[Self::WORD2_RANGE].copy_from_slice(&value.to_be_bytes());
    }

    fn set_word3(&mut self, value: u32) {
        self.bytes[Self::WORD3_RANGE].copy_from_slice(&value.to_be_bytes());
    }

    fn word1(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[20],
            self.bytes[21],
            self.bytes[22],
            self.bytes[23],
        ])
    }

    fn word3(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[28],
            self.bytes[29],
            self.bytes[30],
            self.bytes[31],
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_fields_use_big_endian_encoding() {
        let mut address = Address::new();

        address.set_layer_address(0x0102_0304);
        address.set_tree_address(0x0506_0708_090a_0b0c);
        address.set_type_and_clear(AddressType::WotsHash);
        address.set_key_pair_address(0x0d0e_0f10);
        address.set_chain_address(0x1112_1314);
        address.set_hash_address(0x1516_1718);

        assert_eq!(
            address.as_bytes(),
            &[
                0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18,
            ]
        );
    }

    #[test]
    fn address_types_match_fips_205_assignments() {
        assert_eq!(AddressType::WotsHash as u32, 0);
        assert_eq!(AddressType::WotsPublicKey as u32, 1);
        assert_eq!(AddressType::Tree as u32, 2);
        assert_eq!(AddressType::ForsTree as u32, 3);
        assert_eq!(AddressType::ForsRoots as u32, 4);
        assert_eq!(AddressType::WotsPrf as u32, 5);
        assert_eq!(AddressType::ForsPrf as u32, 6);
    }

    #[test]
    fn changing_type_clears_all_type_dependent_words() {
        let mut address = Address::new();

        address.set_type_and_clear(AddressType::WotsHash);
        address.set_key_pair_address(u32::MAX);
        address.set_chain_address(u32::MAX);
        address.set_hash_address(u32::MAX);

        address.set_type_and_clear(AddressType::Tree);

        assert_eq!(&address.as_bytes()[16..20], &[0, 0, 0, 2]);
        assert_eq!(&address.as_bytes()[20..32], &[0_u8; 12]);
    }

    #[test]
    fn changing_type_preserves_layer_and_tree_addresses() {
        let mut address = Address::new();

        address.set_layer_address(7);
        address.set_tree_address(0x0102_0304_0506_0708);
        address.set_type_and_clear(AddressType::ForsTree);
        address.set_tree_height(9);
        address.set_tree_index(10);

        address.set_type_and_clear(AddressType::ForsRoots);

        assert_eq!(&address.as_bytes()[0..4], &[0, 0, 0, 7]);
        assert_eq!(
            &address.as_bytes()[4..16],
            &[0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!(&address.as_bytes()[20..32], &[0_u8; 12]);
    }

    #[test]
    fn overloaded_address_words_round_trip() {
        let mut address = Address::new();

        address.set_key_pair_address(0x1122_3344);
        address.set_tree_index(0x5566_7788);

        assert_eq!(address.key_pair_address(), 0x1122_3344);
        assert_eq!(address.tree_index(), 0x5566_7788);
    }

    #[test]
    fn compressed_address_matches_fips_205_projection() {
        let mut address = Address::new();

        address.set_layer_address(0x0102_0304);
        address.set_tree_address(0x0506_0708_090a_0b0c);
        address.set_type_and_clear(AddressType::ForsTree);
        address.set_key_pair_address(0x0d0e_0f10);
        address.set_tree_height(0x1112_1314);
        address.set_tree_index(0x1516_1718);

        assert_eq!(
            address.compressed(),
            [
                0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x03, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            ]
        );
    }

    #[test]
    fn hash_family_selects_required_address_encoding() {
        let mut address = Address::new();
        address.set_type_and_clear(AddressType::WotsPrf);

        let sha2 = address.encode_for(SlhDsaHashFamily::Sha2);
        let shake = address.encode_for(SlhDsaHashFamily::Shake);

        assert_eq!(sha2.as_bytes().len(), COMPRESSED_ADDRESS_BYTES);
        assert_eq!(shake.as_bytes().len(), ADDRESS_BYTES);
        assert_eq!(sha2, EncodedAddress::Compressed(address.compressed()));
        assert_eq!(shake, EncodedAddress::Full(*address.as_bytes()));
    }

    #[test]
    fn default_address_is_all_zero() {
        assert_eq!(Address::default(), Address::new());
        assert_eq!(Address::new().as_bytes(), &[0_u8; ADDRESS_BYTES]);
    }
}

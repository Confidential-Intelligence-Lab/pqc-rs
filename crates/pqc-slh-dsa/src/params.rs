//! FIPS 205 SLH-DSA parameter-set definitions.

/// Hash-function family used by an SLH-DSA parameter set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlhDsaHashFamily {
    /// SHA-256-based instantiation.
    Sha2,
    /// SHAKE256-based instantiation.
    Shake,
}

/// Supported FIPS 205 SLH-DSA parameter set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlhDsaParameterSet {
    /// SLH-DSA-SHA2-128s.
    Sha2_128s,
    /// SLH-DSA-SHA2-128f.
    Sha2_128f,
    /// SLH-DSA-SHA2-192s.
    Sha2_192s,
    /// SLH-DSA-SHA2-192f.
    Sha2_192f,
    /// SLH-DSA-SHA2-256s.
    Sha2_256s,
    /// SLH-DSA-SHA2-256f.
    Sha2_256f,
    /// SLH-DSA-SHAKE-128s.
    Shake128s,
    /// SLH-DSA-SHAKE-128f.
    Shake128f,
    /// SLH-DSA-SHAKE-192s.
    Shake192s,
    /// SLH-DSA-SHAKE-192f.
    Shake192f,
    /// SLH-DSA-SHAKE-256s.
    Shake256s,
    /// SLH-DSA-SHAKE-256f.
    Shake256f,
}

/// Immutable FIPS 205 parameters for one SLH-DSA instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlhDsaParameters {
    /// Hash-function family.
    pub hash_family: SlhDsaHashFamily,
    /// Security parameter and hash-output length in bytes.
    pub n: usize,
    /// Total hypertree height.
    pub h: usize,
    /// Number of hypertree layers.
    pub d: usize,
    /// Height of each XMSS tree.
    pub hp: usize,
    /// FORS tree height.
    pub a: usize,
    /// Number of FORS trees.
    pub k: usize,
    /// Message-digest length in bytes.
    pub m: usize,
    /// Public-key length in bytes.
    pub public_key_bytes: usize,
    /// Private-key length in bytes.
    pub private_key_bytes: usize,
    /// Signature length in bytes.
    pub signature_bytes: usize,
    /// External key-generation seed length in bytes.
    pub keygen_seed_bytes: usize,
}

impl SlhDsaParameterSet {
    /// Return the canonical FIPS 205 parameters.
    pub const fn parameters(self) -> SlhDsaParameters {
        match self {
            Self::Sha2_128s => parameters(SlhDsaHashFamily::Sha2, 16, 63, 7, 9, 12, 14, 30, 7_856),
            Self::Sha2_128f => parameters(SlhDsaHashFamily::Sha2, 16, 66, 22, 3, 6, 33, 34, 17_088),
            Self::Sha2_192s => parameters(SlhDsaHashFamily::Sha2, 24, 63, 7, 9, 14, 17, 39, 16_224),
            Self::Sha2_192f => parameters(SlhDsaHashFamily::Sha2, 24, 66, 22, 3, 8, 33, 42, 35_664),
            Self::Sha2_256s => parameters(SlhDsaHashFamily::Sha2, 32, 64, 8, 8, 14, 22, 47, 29_792),
            Self::Sha2_256f => parameters(SlhDsaHashFamily::Sha2, 32, 68, 17, 4, 9, 35, 49, 49_856),
            Self::Shake128s => parameters(SlhDsaHashFamily::Shake, 16, 63, 7, 9, 12, 14, 30, 7_856),
            Self::Shake128f => {
                parameters(SlhDsaHashFamily::Shake, 16, 66, 22, 3, 6, 33, 34, 17_088)
            }
            Self::Shake192s => {
                parameters(SlhDsaHashFamily::Shake, 24, 63, 7, 9, 14, 17, 39, 16_224)
            }
            Self::Shake192f => {
                parameters(SlhDsaHashFamily::Shake, 24, 66, 22, 3, 8, 33, 42, 35_664)
            }
            Self::Shake256s => {
                parameters(SlhDsaHashFamily::Shake, 32, 64, 8, 8, 14, 22, 47, 29_792)
            }
            Self::Shake256f => {
                parameters(SlhDsaHashFamily::Shake, 32, 68, 17, 4, 9, 35, 49, 49_856)
            }
        }
    }

    /// Return the canonical parameter-set name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha2_128s => "SLH-DSA-SHA2-128s",
            Self::Sha2_128f => "SLH-DSA-SHA2-128f",
            Self::Sha2_192s => "SLH-DSA-SHA2-192s",
            Self::Sha2_192f => "SLH-DSA-SHA2-192f",
            Self::Sha2_256s => "SLH-DSA-SHA2-256s",
            Self::Sha2_256f => "SLH-DSA-SHA2-256f",
            Self::Shake128s => "SLH-DSA-SHAKE-128s",
            Self::Shake128f => "SLH-DSA-SHAKE-128f",
            Self::Shake192s => "SLH-DSA-SHAKE-192s",
            Self::Shake192f => "SLH-DSA-SHAKE-192f",
            Self::Shake256s => "SLH-DSA-SHAKE-256s",
            Self::Shake256f => "SLH-DSA-SHAKE-256f",
        }
    }
}

#[allow(clippy::too_many_arguments)]
const fn parameters(
    hash_family: SlhDsaHashFamily,
    n: usize,
    h: usize,
    d: usize,
    hp: usize,
    a: usize,
    k: usize,
    m: usize,
    signature_bytes: usize,
) -> SlhDsaParameters {
    SlhDsaParameters {
        hash_family,
        n,
        h,
        d,
        hp,
        a,
        k,
        m,
        public_key_bytes: 2 * n,
        private_key_bytes: 4 * n,
        signature_bytes,
        keygen_seed_bytes: 3 * n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARAMETER_SETS: [SlhDsaParameterSet; 12] = [
        SlhDsaParameterSet::Sha2_128s,
        SlhDsaParameterSet::Sha2_128f,
        SlhDsaParameterSet::Sha2_192s,
        SlhDsaParameterSet::Sha2_192f,
        SlhDsaParameterSet::Sha2_256s,
        SlhDsaParameterSet::Sha2_256f,
        SlhDsaParameterSet::Shake128s,
        SlhDsaParameterSet::Shake128f,
        SlhDsaParameterSet::Shake192s,
        SlhDsaParameterSet::Shake192f,
        SlhDsaParameterSet::Shake256s,
        SlhDsaParameterSet::Shake256f,
    ];

    #[test]
    fn every_parameter_set_has_consistent_tree_dimensions() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            assert_eq!(parameters.h, parameters.d * parameters.hp);
        }
    }

    #[test]
    fn encoded_key_lengths_are_derived_from_n() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            assert_eq!(parameters.public_key_bytes, 2 * parameters.n);
            assert_eq!(parameters.private_key_bytes, 4 * parameters.n);
            assert_eq!(parameters.keygen_seed_bytes, 3 * parameters.n);
        }
    }

    #[test]
    fn paired_hash_families_have_identical_structural_parameters() {
        let pairs = [
            (SlhDsaParameterSet::Sha2_128s, SlhDsaParameterSet::Shake128s),
            (SlhDsaParameterSet::Sha2_128f, SlhDsaParameterSet::Shake128f),
            (SlhDsaParameterSet::Sha2_192s, SlhDsaParameterSet::Shake192s),
            (SlhDsaParameterSet::Sha2_192f, SlhDsaParameterSet::Shake192f),
            (SlhDsaParameterSet::Sha2_256s, SlhDsaParameterSet::Shake256s),
            (SlhDsaParameterSet::Sha2_256f, SlhDsaParameterSet::Shake256f),
        ];

        for (sha2, shake) in pairs {
            let mut sha2_parameters = sha2.parameters();
            let mut shake_parameters = shake.parameters();
            sha2_parameters.hash_family = SlhDsaHashFamily::Shake;
            shake_parameters.hash_family = SlhDsaHashFamily::Shake;
            assert_eq!(sha2_parameters, shake_parameters);
        }
    }
}

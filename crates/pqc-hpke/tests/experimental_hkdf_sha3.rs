#![cfg(all(feature = "experimental-hkdf-sha3", feature = "internal-api"))]

use pqc_hpke::internal_api::kdf::KdfAlgorithm;
use pqc_hpke::{AeadId, HpkeError, HpkeSuiteId, KdfId, KemId};

#[test]
fn sha3_labeled_hkdf_matches_independent_reference() {
    let kdf = KdfAlgorithm::HkdfSha3_256;

    let suite = HpkeSuiteId {
        kem_id: KemId(0x0041),
        kdf_id: KdfId::EXPERIMENTAL_HKDF_SHA3_256,
        aead_id: AeadId::AES_256_GCM,
    }
    .to_bytes();

    let salt: Vec<u8> = (0u8..32).collect();
    let ikm: Vec<u8> = (0u8..64).collect();

    let prk = kdf.labeled_extract(&suite, &salt, b"test-extract", &ikm);

    assert_eq!(
        hex::encode(&prk),
        "52a2f0f81b34f8af02dc9ddf8fcbfd65d15cdd4dc9dbbd703fae825263287a4f"
    );

    let output = kdf
        .labeled_expand(
            &suite,
            &prk,
            b"test-expand",
            b"experimental-hkdf-sha3-256",
            80,
        )
        .unwrap();

    assert_eq!(
        hex::encode(output),
        "0ad30a2c563440e673feb10a7e49420479962f6c60856af40fad9299c2ac1b0172e8b7ba928eda7c88d0bac793bd4dbb48be5fd017f918a5444867c83f9abb39bd9de4f61bef256fe323e2f881407fe0"
    );
}

#[test]
fn sha3_kdf_identifier_and_dimensions() {
    let kdf = KdfAlgorithm::HkdfSha3_256;

    assert_eq!(kdf.hash_length(), 32);

    assert_eq!(kdf.id(), KdfId::EXPERIMENTAL_HKDF_SHA3_256);

    assert_eq!(KdfAlgorithm::from_id(kdf.id()), Some(kdf));
}

#[test]
fn sha3_expansion_boundaries() {
    let kdf = KdfAlgorithm::HkdfSha3_256;
    let prk = [0x42u8; 32];

    for length in [0, 1, 31, 32, 33, 8160] {
        let output = kdf
            .labeled_expand(b"suite", &prk, b"key", b"context", length)
            .unwrap();

        assert_eq!(output.len(), length);
    }

    assert_eq!(
        kdf.labeled_expand(b"suite", &prk, b"key", b"context", 8161),
        Err(HpkeError::OutputTooLong)
    );

    assert_eq!(
        kdf.labeled_expand(b"suite", &[0u8; 31], b"key", b"context", 32),
        Err(HpkeError::InvalidPrk)
    );
}

#[test]
fn sha3_and_sha2_are_distinct() {
    let sha3 = KdfAlgorithm::HkdfSha3_256;
    let sha2 = KdfAlgorithm::HkdfSha256;

    let lhs = sha3.labeled_extract(b"suite", b"salt", b"label", b"ikm");

    let rhs = sha2.labeled_extract(b"suite", b"salt", b"label", b"ikm");

    assert_ne!(lhs, rhs);
}

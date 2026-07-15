use pqc_ml_dsa::{
    hash_mldsa::{hash_message_prime, hash_sign, hash_verify, HashMlDsaError, PreHashAlgorithm},
    keygen::keygen_internal,
    params::MlDsaParameterSet,
};

#[test]
fn all_hash_algorithms_round_trip() {
    let algorithms = [
        PreHashAlgorithm::Sha2_224,
        PreHashAlgorithm::Sha2_256,
        PreHashAlgorithm::Sha2_384,
        PreHashAlgorithm::Sha2_512,
        PreHashAlgorithm::Sha2_512_224,
        PreHashAlgorithm::Sha2_512_256,
        PreHashAlgorithm::Sha3_224,
        PreHashAlgorithm::Sha3_256,
        PreHashAlgorithm::Sha3_384,
        PreHashAlgorithm::Sha3_512,
        PreHashAlgorithm::Shake128,
        PreHashAlgorithm::Shake256,
    ];

    for set in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        let key_pair = keygen_internal(set, &[0x5a; 32]).unwrap();

        for algorithm in algorithms {
            let signature = hash_sign(
                set,
                key_pair.private_key(),
                b"message",
                b"ctx",
                algorithm,
                &[0_u8; 32],
            )
            .unwrap();

            assert!(hash_verify(
                set,
                key_pair.public_key(),
                b"message",
                b"ctx",
                algorithm,
                &signature,
            )
            .unwrap());
        }
    }
}

#[test]
fn domain_separator_and_oid_are_present() {
    let message_prime = hash_message_prime(b"message", b"ctx", PreHashAlgorithm::Sha2_256).unwrap();

    assert_eq!(&message_prime[..5], &[1, 3, b'c', b't', b'x']);
    assert_eq!(
        &message_prime[5..16],
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    );
}

#[test]
fn context_limit_is_strict() {
    assert!(matches!(
        hash_message_prime(b"message", &[0_u8; 256], PreHashAlgorithm::Sha2_256,),
        Err(HashMlDsaError::ContextTooLong)
    ));
}

use pqc_slh_dsa::{
    SlhDsa, SlhDsaError, SlhDsaKeyGenSeed, SlhDsaParameterSet, SlhDsaPreHash, SlhDsaPublicKey,
    SlhDsaSignature,
};

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

fn key_pair(parameter_set: SlhDsaParameterSet, domain: u8) -> pqc_slh_dsa::SlhDsaKeyPair {
    let parameters = parameter_set.parameters();
    let seed_bytes: Vec<u8> = (0..parameters.keygen_seed_bytes)
        .map(|offset| domain.wrapping_add(offset as u8))
        .collect();
    let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes).unwrap();
    SlhDsa::new(parameter_set).keygen_from_seed(&seed).unwrap()
}

fn mutated_signature(
    parameter_set: SlhDsaParameterSet,
    signature: &SlhDsaSignature,
    index: usize,
) -> SlhDsaSignature {
    let mut bytes = signature.as_bytes().to_vec();
    bytes[index] ^= 1;
    SlhDsaSignature::from_bytes(parameter_set, &bytes).unwrap()
}

#[test]
fn pure_adversarial_campaign_all_parameter_sets() {
    let message = b"SLH-DSA adversarial campaign";
    let context = b"pqc-rs-s4";

    for (index, parameter_set) in PARAMETER_SETS.into_iter().enumerate() {
        println!("[Pure {}/12] {}", index + 1, parameter_set.name());

        let parameters = parameter_set.parameters();
        let slh = SlhDsa::new(parameter_set);
        let signer = key_pair(parameter_set, 0x31);
        let other = key_pair(parameter_set, 0xa1);

        let signature = slh
            .sign_deterministic(signer.private_key(), message, context)
            .unwrap();

        assert_eq!(
            slh.verify(signer.public_key(), message, context, &signature),
            Ok(true),
            "{} valid baseline",
            parameter_set.name()
        );

        assert_eq!(
            slh.verify(
                signer.public_key(),
                b"SLH-DSA adversarial campaigo",
                context,
                &signature
            ),
            Ok(false),
            "{} changed message",
            parameter_set.name()
        );

        assert_eq!(
            slh.verify(signer.public_key(), message, b"pqc-rs-s5", &signature),
            Ok(false),
            "{} changed context",
            parameter_set.name()
        );

        assert_eq!(
            slh.verify(other.public_key(), message, context, &signature),
            Ok(false),
            "{} different public key",
            parameter_set.name()
        );

        let fors_bytes = parameters.k * (parameters.a + 1) * parameters.n;
        let fors_start = parameters.n;
        let fors_end = fors_start + fors_bytes;

        let mutation_points = [
            ("R", 0usize),
            ("FORS-first", fors_start),
            ("FORS-last", fors_end - 1),
            ("HT-first", fors_end),
            ("HT-last", parameters.signature_bytes - 1),
        ];

        for (region, index) in mutation_points {
            let modified = mutated_signature(parameter_set, &signature, index);
            assert_eq!(
                slh.verify(signer.public_key(), message, context, &modified),
                Ok(false),
                "{} corrupted {}",
                parameter_set.name(),
                region
            );
        }

        let signature_bytes = signature.as_bytes();

        assert!(
            SlhDsaSignature::from_bytes(
                parameter_set,
                &signature_bytes[..signature_bytes.len() - 1]
            )
            .is_err(),
            "{} truncated signature accepted",
            parameter_set.name()
        );

        let mut oversized_signature = signature_bytes.to_vec();
        oversized_signature.push(0);
        assert!(
            SlhDsaSignature::from_bytes(parameter_set, &oversized_signature).is_err(),
            "{} oversized signature accepted",
            parameter_set.name()
        );

        let public_key_bytes = signer.public_key().as_bytes();

        assert!(
            SlhDsaPublicKey::from_bytes(
                parameter_set,
                &public_key_bytes[..public_key_bytes.len() - 1]
            )
            .is_err(),
            "{} truncated public key accepted",
            parameter_set.name()
        );

        let mut oversized_public_key = public_key_bytes.to_vec();
        oversized_public_key.push(0);
        assert!(
            SlhDsaPublicKey::from_bytes(parameter_set, &oversized_public_key).is_err(),
            "{} oversized public key accepted",
            parameter_set.name()
        );

        let context_255 = [0x5a_u8; 255];
        let boundary_signature = slh
            .sign_deterministic(signer.private_key(), message, &context_255)
            .unwrap();
        assert_eq!(
            slh.verify(
                signer.public_key(),
                message,
                &context_255,
                &boundary_signature
            ),
            Ok(true),
            "{} 255-byte context",
            parameter_set.name()
        );

        let context_256 = [0x5a_u8; 256];
        assert_eq!(
            slh.sign_deterministic(signer.private_key(), message, &context_256)
                .err(),
            Some(SlhDsaError::ContextTooLong),
            "{} 256-byte signing context",
            parameter_set.name()
        );

        assert_eq!(
            slh.verify(signer.public_key(), message, &context_256, &signature)
                .err(),
            Some(SlhDsaError::ContextTooLong),
            "{} 256-byte verification context",
            parameter_set.name()
        );
    }
}

#[test]
fn hash_slhdsa_binding_campaign_all_parameter_sets() {
    let message = b"HashSLH-DSA adversarial campaign";
    let context = b"pqc-rs-s4-hash";

    for (index, parameter_set) in PARAMETER_SETS.into_iter().enumerate() {
        println!("[HashSLH {}/12] {}", index + 1, parameter_set.name());

        let slh = SlhDsa::new(parameter_set);
        let signer = key_pair(parameter_set, 0x51);

        let signature = slh
            .hash_sign_deterministic(
                signer.private_key(),
                message,
                context,
                SlhDsaPreHash::Sha2_256,
            )
            .unwrap();

        assert_eq!(
            slh.hash_verify(
                signer.public_key(),
                message,
                context,
                SlhDsaPreHash::Sha2_256,
                &signature
            ),
            Ok(true),
            "{} HashSLH valid baseline",
            parameter_set.name()
        );

        assert_eq!(
            slh.hash_verify(
                signer.public_key(),
                b"HashSLH-DSA adversarial campaigo",
                context,
                SlhDsaPreHash::Sha2_256,
                &signature
            ),
            Ok(false),
            "{} HashSLH changed message",
            parameter_set.name()
        );

        assert_eq!(
            slh.hash_verify(
                signer.public_key(),
                message,
                b"pqc-rs-s4-other",
                SlhDsaPreHash::Sha2_256,
                &signature
            ),
            Ok(false),
            "{} HashSLH changed context",
            parameter_set.name()
        );

        assert_eq!(
            slh.hash_verify(
                signer.public_key(),
                message,
                context,
                SlhDsaPreHash::Sha2_512,
                &signature
            ),
            Ok(false),
            "{} HashSLH wrong prehash",
            parameter_set.name()
        );
    }
}

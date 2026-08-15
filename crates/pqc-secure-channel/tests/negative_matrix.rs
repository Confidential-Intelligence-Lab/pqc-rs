use pqc_hpke::{HpkeError, MlKemHpke};
use pqc_protocol::{
    negotiate_policy_permitted_common, CapabilityId, CapabilityOffer, CapabilityOfferError,
    CapabilityPolicy, CapabilityPolicyError, EstablishedProtocolContext, PolicyId, ProtocolId,
    ProtocolRole, ProtocolVersion, SessionId, TypedProtocolSession, HPKE_ML_KEM_1024,
    HPKE_ML_KEM_768,
};
use pqc_secure_channel::{
    activate_receiver, activate_sender, HpkeProfileResolutionError, SecureChannelError,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

const PROTOCOL_ID: ProtocolId = ProtocolId::new(0x1300);
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

struct DeterministicRng {
    next: u8,
}

impl DeterministicRng {
    const fn new(seed: u8) -> Self {
        Self { next: seed }
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}

#[derive(Debug)]
struct EvaluationRecord {
    id: &'static str,
    case: &'static str,
    expected_boundary: &'static str,
    actual_boundary: &'static str,
    outcome: &'static str,
    plaintext_released: bool,
    sequence_before: Option<u64>,
    sequence_after: Option<u64>,
    passed: bool,
}

impl EvaluationRecord {
    fn emit(&self) {
        println!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.id,
            self.case,
            self.expected_boundary,
            self.actual_boundary,
            self.outcome,
            self.plaintext_released,
            optional_sequence(self.sequence_before),
            optional_sequence(self.sequence_after),
            if self.passed { "PASS" } else { "FAIL" },
        );
    }
}

fn optional_sequence(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn established(
    capability: CapabilityId,
    policy_id: PolicyId,
    session_byte: u8,
    protocol_id: ProtocolId,
    protocol_version: ProtocolVersion,
    role: ProtocolRole,
) -> EstablishedProtocolContext {
    let local_ids = [capability];
    let peer_ids = [capability];
    let allowed = [capability];

    let local = CapabilityOffer::new(&local_ids).unwrap();
    let peer = CapabilityOffer::new(&peer_ids).unwrap();
    let policy = CapabilityPolicy::new(policy_id, &allowed).unwrap();

    let negotiated = negotiate_policy_permitted_common(local, peer, policy).unwrap();

    TypedProtocolSession::new(
        SessionId::from_bytes([session_byte; 16]),
        protocol_id,
        protocol_version,
        role,
    )
    .begin_establishment()
    .establish_with_negotiation(negotiated)
}

fn endpoint_pair(
    capability: CapabilityId,
) -> (EstablishedProtocolContext, EstablishedProtocolContext) {
    (
        established(
            capability,
            PolicyId::new(0x101),
            0x41,
            PROTOCOL_ID,
            PROTOCOL_VERSION,
            ProtocolRole::Client,
        ),
        established(
            capability,
            PolicyId::new(0x202),
            0x42,
            PROTOCOL_ID,
            PROTOCOL_VERSION,
            ProtocolRole::Server,
        ),
    )
}

fn ml_kem_768_key_material(seed: u8) -> (Vec<u8>, Vec<u8>) {
    let key_pair = MlKemHpke::MlKem768.derive_key_pair(&[seed; 64]).unwrap();

    (
        key_pair.public_key,
        key_pair.private_key_seed.as_bytes().to_vec(),
    )
}

fn open_error(error: &SecureChannelError) -> bool {
    matches!(error, SecureChannelError::Hpke(HpkeError::OpenError))
}

#[test]
fn frozen_negative_matrix_matches_expected_boundaries() {
    let mut records = Vec::new();

    // N1: duplicate local capability offer.
    let duplicate_offer = [HPKE_ML_KEM_768, HPKE_ML_KEM_768];
    let n1 = matches!(
        CapabilityOffer::new(&duplicate_offer),
        Err(CapabilityOfferError::DuplicateCapability { capability })
            if capability == HPKE_ML_KEM_768
    );

    records.push(EvaluationRecord {
        id: "N1",
        case: "duplicate local capability offer",
        expected_boundary: "offer validation",
        actual_boundary: "offer validation",
        outcome: "DuplicateCapability",
        plaintext_released: false,
        sequence_before: None,
        sequence_after: None,
        passed: n1,
    });

    // N2: duplicate policy capability.
    let duplicate_policy = [HPKE_ML_KEM_768, HPKE_ML_KEM_768];
    let n2 = matches!(
        CapabilityPolicy::new(PolicyId::new(1), &duplicate_policy),
        Err(CapabilityPolicyError::DuplicateCapability { capability })
            if capability == HPKE_ML_KEM_768
    );

    records.push(EvaluationRecord {
        id: "N2",
        case: "duplicate policy capability",
        expected_boundary: "policy validation",
        actual_boundary: "policy validation",
        outcome: "DuplicateCapability",
        plaintext_released: false,
        sequence_before: None,
        sequence_after: None,
        passed: n2,
    });

    // N3: structurally valid inputs with no policy-permitted common capability.
    let local_ids = [HPKE_ML_KEM_768];
    let peer_ids = [HPKE_ML_KEM_768];
    let allowed = [HPKE_ML_KEM_1024];

    let local = CapabilityOffer::new(&local_ids).unwrap();
    let peer = CapabilityOffer::new(&peer_ids).unwrap();
    let policy = CapabilityPolicy::new(PolicyId::new(2), &allowed).unwrap();

    let n3 = negotiate_policy_permitted_common(local, peer, policy).is_none();

    records.push(EvaluationRecord {
        id: "N3",
        case: "no policy-permitted common capability",
        expected_boundary: "negotiation",
        actual_boundary: "negotiation",
        outcome: "None",
        plaintext_released: false,
        sequence_before: None,
        sequence_after: None,
        passed: n3,
    });

    // N4: unsupported negotiated capability must fail before HPKE setup.
    let unsupported = CapabilityId::new(0xfefe);
    let context = established(
        unsupported,
        PolicyId::new(3),
        0x43,
        PROTOCOL_ID,
        PROTOCOL_VERSION,
        ProtocolRole::Client,
    );

    let mut rng = DeterministicRng::new(0x40);
    let n4_result = activate_sender(&context, &[0_u8; 32], b"e4", &mut rng);

    let n4 = matches!(
        n4_result,
        Err(SecureChannelError::ProfileResolution(
            HpkeProfileResolutionError::UnsupportedCapability { capability }
        )) if capability == unsupported
    );

    records.push(EvaluationRecord {
        id: "N4",
        case: "unsupported negotiated capability",
        expected_boundary: "profile resolution",
        actual_boundary: "profile resolution",
        outcome: "UnsupportedCapability",
        plaintext_released: false,
        sequence_before: None,
        sequence_after: None,
        passed: n4,
    });

    // N5: malformed recipient public key.
    let (client, _) = endpoint_pair(HPKE_ML_KEM_768);
    let mut rng = DeterministicRng::new(0x50);

    let n5 = matches!(
        activate_sender(&client, &[0_u8; 7], b"e4", &mut rng),
        Err(SecureChannelError::Hpke(_))
    );

    records.push(EvaluationRecord {
        id: "N5",
        case: "malformed recipient public key",
        expected_boundary: "sender activation",
        actual_boundary: "sender activation",
        outcome: "HPKE/KEM error",
        plaintext_released: false,
        sequence_before: None,
        sequence_after: None,
        passed: n5,
    });

    // N6: malformed recipient private material.
    let (client, server) = endpoint_pair(HPKE_ML_KEM_768);
    let (public_key, _) = ml_kem_768_key_material(0x60);
    let mut rng = DeterministicRng::new(0x60);

    let activation = activate_sender(&client, &public_key, b"e4", &mut rng).unwrap();

    let n6 = matches!(
        activate_receiver(&server, &[0_u8; 7], activation.encapsulated_key(), b"e4",),
        Err(SecureChannelError::Hpke(_))
    );

    records.push(EvaluationRecord {
        id: "N6",
        case: "malformed recipient private material",
        expected_boundary: "receiver activation",
        actual_boundary: "receiver activation",
        outcome: "HPKE/KEM error",
        plaintext_released: false,
        sequence_before: None,
        sequence_after: None,
        passed: n6,
    });

    // N7: malformed encapsulated key with otherwise valid recipient key.
    let (client, server) = endpoint_pair(HPKE_ML_KEM_768);
    let (public_key, private_key) = ml_kem_768_key_material(0x70);
    let mut rng = DeterministicRng::new(0x70);

    let _activation = activate_sender(&client, &public_key, b"e4", &mut rng).unwrap();

    let n7 = matches!(
        activate_receiver(&server, &private_key, &[0_u8; 7], b"e4"),
        Err(SecureChannelError::Hpke(_))
    );

    records.push(EvaluationRecord {
        id: "N7",
        case: "malformed encapsulated key",
        expected_boundary: "receiver activation",
        actual_boundary: "receiver activation",
        outcome: "HPKE/KEM error",
        plaintext_released: false,
        sequence_before: None,
        sequence_after: None,
        passed: n7,
    });

    // N8: sender and receiver negotiated different KEM capabilities.
    let client = established(
        HPKE_ML_KEM_768,
        PolicyId::new(8),
        0x41,
        PROTOCOL_ID,
        PROTOCOL_VERSION,
        ProtocolRole::Client,
    );

    let server = established(
        HPKE_ML_KEM_1024,
        PolicyId::new(9),
        0x42,
        PROTOCOL_ID,
        PROTOCOL_VERSION,
        ProtocolRole::Server,
    );

    let (public_key, private_key) = ml_kem_768_key_material(0x80);
    let mut rng = DeterministicRng::new(0x80);
    let activation = activate_sender(&client, &public_key, b"e4", &mut rng).unwrap();

    let n8 = matches!(
        activate_receiver(&server, &private_key, activation.encapsulated_key(), b"e4",),
        Err(SecureChannelError::Hpke(_))
    );

    records.push(EvaluationRecord {
        id: "N8",
        case: "peer negotiated-capability mismatch",
        expected_boundary: "receiver activation",
        actual_boundary: "receiver activation",
        outcome: "HPKE/KEM error",
        plaintext_released: false,
        sequence_before: None,
        sequence_after: None,
        passed: n8,
    });

    // N9: protocol identifier mismatch.
    {
        let client = established(
            HPKE_ML_KEM_768,
            PolicyId::new(10),
            0x41,
            ProtocolId::new(0x1300),
            PROTOCOL_VERSION,
            ProtocolRole::Client,
        );

        let server = established(
            HPKE_ML_KEM_768,
            PolicyId::new(11),
            0x42,
            ProtocolId::new(0x1301),
            PROTOCOL_VERSION,
            ProtocolRole::Server,
        );

        let (public_key, private_key) = ml_kem_768_key_material(0x90);
        let mut rng = DeterministicRng::new(0x90);

        let activation = activate_sender(&client, &public_key, b"e4", &mut rng).unwrap();
        let (enc, mut sender) = activation.into_parts();
        let mut receiver = activate_receiver(&server, &private_key, &enc, b"e4").unwrap();

        let ciphertext = sender.seal(b"aad", b"message").unwrap();
        let before = receiver.sequence_number();
        let result = receiver.open(b"aad", &ciphertext);
        let after = receiver.sequence_number();

        let passed =
            matches!(&result, Err(error) if open_error(error)) && before == 0 && after == 0;

        records.push(EvaluationRecord {
            id: "N9",
            case: "protocol identifier mismatch",
            expected_boundary: "protected-message authentication",
            actual_boundary: "protected-message authentication",
            outcome: "OpenError",
            plaintext_released: result.is_ok(),
            sequence_before: Some(before),
            sequence_after: Some(after),
            passed,
        });
    }

    // N10: protocol version mismatch.
    {
        let client = established(
            HPKE_ML_KEM_768,
            PolicyId::new(12),
            0x41,
            PROTOCOL_ID,
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        );

        let server = established(
            HPKE_ML_KEM_768,
            PolicyId::new(13),
            0x42,
            PROTOCOL_ID,
            ProtocolVersion::new(1, 1),
            ProtocolRole::Server,
        );

        let (public_key, private_key) = ml_kem_768_key_material(0xa0);
        let mut rng = DeterministicRng::new(0xa0);

        let activation = activate_sender(&client, &public_key, b"e4", &mut rng).unwrap();
        let (enc, mut sender) = activation.into_parts();
        let mut receiver = activate_receiver(&server, &private_key, &enc, b"e4").unwrap();

        let ciphertext = sender.seal(b"aad", b"message").unwrap();
        let before = receiver.sequence_number();
        let result = receiver.open(b"aad", &ciphertext);
        let after = receiver.sequence_number();

        let passed =
            matches!(&result, Err(error) if open_error(error)) && before == 0 && after == 0;

        records.push(EvaluationRecord {
            id: "N10",
            case: "protocol version mismatch",
            expected_boundary: "protected-message authentication",
            actual_boundary: "protected-message authentication",
            outcome: "OpenError",
            plaintext_released: result.is_ok(),
            sequence_before: Some(before),
            sequence_after: Some(after),
            passed,
        });
    }

    // N11: application context mismatch.
    {
        let (client, server) = endpoint_pair(HPKE_ML_KEM_768);
        let (public_key, private_key) = ml_kem_768_key_material(0xb0);
        let mut rng = DeterministicRng::new(0xb0);

        let activation = activate_sender(&client, &public_key, b"application-a", &mut rng).unwrap();

        let (enc, mut sender) = activation.into_parts();

        let mut receiver =
            activate_receiver(&server, &private_key, &enc, b"application-b").unwrap();

        let ciphertext = sender.seal(b"aad", b"message").unwrap();
        let before = receiver.sequence_number();
        let result = receiver.open(b"aad", &ciphertext);
        let after = receiver.sequence_number();

        let passed =
            matches!(&result, Err(error) if open_error(error)) && before == 0 && after == 0;

        records.push(EvaluationRecord {
            id: "N11",
            case: "application-context mismatch",
            expected_boundary: "protected-message authentication",
            actual_boundary: "protected-message authentication",
            outcome: "OpenError",
            plaintext_released: result.is_ok(),
            sequence_before: Some(before),
            sequence_after: Some(after),
            passed,
        });
    }

    // N12: modified ciphertext.
    {
        let (client, server) = endpoint_pair(HPKE_ML_KEM_768);
        let (public_key, private_key) = ml_kem_768_key_material(0xc0);
        let mut rng = DeterministicRng::new(0xc0);

        let activation = activate_sender(&client, &public_key, b"e4", &mut rng).unwrap();
        let (enc, mut sender) = activation.into_parts();
        let mut receiver = activate_receiver(&server, &private_key, &enc, b"e4").unwrap();

        let ciphertext = sender.seal(b"aad", b"message").unwrap();
        let mut modified = ciphertext;
        modified[0] ^= 1;

        let before = receiver.sequence_number();
        let result = receiver.open(b"aad", &modified);
        let after = receiver.sequence_number();

        let passed =
            matches!(&result, Err(error) if open_error(error)) && before == 0 && after == 0;

        records.push(EvaluationRecord {
            id: "N12",
            case: "modified ciphertext",
            expected_boundary: "protected-message authentication",
            actual_boundary: "protected-message authentication",
            outcome: "OpenError",
            plaintext_released: result.is_ok(),
            sequence_before: Some(before),
            sequence_after: Some(after),
            passed,
        });
    }

    // N13: wrong AAD.
    {
        let (client, server) = endpoint_pair(HPKE_ML_KEM_768);
        let (public_key, private_key) = ml_kem_768_key_material(0xd0);
        let mut rng = DeterministicRng::new(0xd0);

        let activation = activate_sender(&client, &public_key, b"e4", &mut rng).unwrap();
        let (enc, mut sender) = activation.into_parts();
        let mut receiver = activate_receiver(&server, &private_key, &enc, b"e4").unwrap();

        let ciphertext = sender.seal(b"correct-aad", b"message").unwrap();

        let before = receiver.sequence_number();
        let result = receiver.open(b"wrong-aad", &ciphertext);
        let after = receiver.sequence_number();

        let passed =
            matches!(&result, Err(error) if open_error(error)) && before == 0 && after == 0;

        records.push(EvaluationRecord {
            id: "N13",
            case: "wrong AAD",
            expected_boundary: "protected-message authentication",
            actual_boundary: "protected-message authentication",
            outcome: "OpenError",
            plaintext_released: result.is_ok(),
            sequence_before: Some(before),
            sequence_after: Some(after),
            passed,
        });
    }

    // N14: valid message remains usable after an authentication failure.
    {
        let (client, server) = endpoint_pair(HPKE_ML_KEM_768);
        let (public_key, private_key) = ml_kem_768_key_material(0xe0);
        let mut rng = DeterministicRng::new(0xe0);

        let activation = activate_sender(&client, &public_key, b"e4", &mut rng).unwrap();
        let (enc, mut sender) = activation.into_parts();
        let mut receiver = activate_receiver(&server, &private_key, &enc, b"e4").unwrap();

        let ciphertext = sender.seal(b"aad", b"message").unwrap();
        let mut modified = ciphertext.clone();
        modified[0] ^= 1;

        let before = receiver.sequence_number();
        let failed = receiver.open(b"aad", &modified);
        let after_failure = receiver.sequence_number();

        let valid = receiver.open(b"aad", &ciphertext);
        let after_success = receiver.sequence_number();

        let valid_plaintext = matches!(
            valid.as_deref(),
            Ok(plaintext) if plaintext == b"message"
        );

        let passed = matches!(&failed, Err(error) if open_error(error))
            && after_failure == before
            && valid_plaintext
            && after_success == before + 1;

        records.push(EvaluationRecord {
            id: "N14",
            case: "valid message after failed authentication",
            expected_boundary: "protected-message processing",
            actual_boundary: "protected-message processing",
            outcome: "valid open succeeds after rejected open",
            plaintext_released: valid.is_ok(),
            sequence_before: Some(before),
            sequence_after: Some(after_success),
            passed,
        });
    }

    println!(
        "id|case|expected_boundary|actual_boundary|outcome|plaintext_released|sequence_before|sequence_after|result"
    );

    for record in &records {
        record.emit();
    }

    assert_eq!(records.len(), 14);
    assert!(
        records.iter().all(|record| record.passed),
        "one or more frozen E4 negative cases failed"
    );
}

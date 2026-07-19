#![no_main]

use libfuzzer_sys::fuzz_target;
use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId};
use pqc_hpke::ml_kem::MlKemHpke;
use pqc_hpke::setup::{
    setup_base_receiver, setup_base_sender_deterministic,
};

fuzz_target!(|data: &[u8]| {
    let kem = MlKemHpke::MlKem512;
    let suite = HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_128_GCM,
    };

    let key_pair = match kem.derive_key_pair(&[0x11; 64]) {
        Ok(value) => value,
        Err(_) => return,
    };

    let sender = match setup_base_sender_deterministic(
        kem,
        suite,
        &key_pair.public_key,
        b"stage8b-fuzz",
        &[0x22; 32],
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    let mut receiver = match setup_base_receiver(
        kem,
        suite,
        key_pair.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        b"stage8b-fuzz",
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    let split = data.len().min(64);
    let aad = &data[..split];
    let ciphertext = &data[split..];

    let sequence_before = receiver.sequence_number();
    let result = receiver.open(aad, ciphertext);

    if result.is_err() {
        assert_eq!(receiver.sequence_number(), sequence_before);
    }
});

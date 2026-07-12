use pqc_hpke::ml_kem::MlKemHpke;

#[test]
fn pure_ml_kem_hpke_kem_adapters_round_trip() {
    let ikm = [0x31u8; 64];
    let randomness = [0x72u8; 32];

    for kem in [
        MlKemHpke::MlKem512,
        MlKemHpke::MlKem768,
        MlKemHpke::MlKem1024,
    ] {
        let key_pair = kem.derive_key_pair(&ikm).unwrap();
        let sender = kem
            .encapsulate_deterministic(&key_pair.public_key, &randomness)
            .unwrap();
        let receiver = kem
            .decapsulate(
                key_pair.private_key_seed.as_bytes(),
                &sender.encapsulated_key,
            )
            .unwrap();

        assert!(sender.shared_secret.as_bytes() == receiver.as_slice());
        assert_eq!(sender.encapsulated_key.len(), kem.encapsulation_length());
    }
}

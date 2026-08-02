use pqc_hpke::{
    setup_base_sender_with_suite, AeadId, HpkeError, HpkeSuite, KdfId, MlKemHpke, MlKemHpkeError,
};

use rand_core::{CryptoRng, Error, RngCore};

struct FailingRng;

impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("fill_bytes should not be used");
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::new("intentional failure"))
    }
}

impl CryptoRng for FailingRng {}

#[test]
fn generate_key_pair_reports_rng_failure() {
    let mut rng = FailingRng;

    assert!(matches!(
        MlKemHpke::MlKem768.generate_key_pair(&mut rng),
        Err(MlKemHpkeError::RandomnessFailure),
    ));
}

#[test]
fn setup_base_sender_reports_rng_failure() {
    let kem = MlKemHpke::MlKem768;

    let key_pair = kem.derive_key_pair(&[0x11; 64]).unwrap();

    let suite = HpkeSuite::new(kem, KdfId::HKDF_SHA256, AeadId::AES_128_GCM).unwrap();

    let mut rng = FailingRng;

    assert!(matches!(
        setup_base_sender_with_suite(kem, suite, &key_pair.public_key, b"rng failure", &mut rng,),
        Err(HpkeError::RandomnessFailure),
    ));
}

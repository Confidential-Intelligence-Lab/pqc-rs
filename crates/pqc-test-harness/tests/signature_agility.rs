use pqc_core::{PqcResult, SignatureScheme};
use pqc_ml_dsa::{MlDsa, MlDsaParameterSet};
use pqc_slh_dsa::{SlhDsa, SlhDsaParameterSet};
use rand_core::{CryptoRng, RngCore};

/// Deterministic test RNG.
///
/// This is test infrastructure only. It is not intended for production
/// cryptographic use.
struct TestRng(u64);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64* is sufficient for deterministic test plumbing.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;

        while offset < dest.len() {
            let bytes = self.next_u64().to_le_bytes();
            let remaining = dest.len() - offset;
            let take = remaining.min(bytes.len());

            dest[offset..offset + take].copy_from_slice(&bytes[..take]);
            offset += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

fn exercise_signature_scheme<S, R>(scheme: &S, rng: &mut R) -> PqcResult<()>
where
    S: SignatureScheme,
    R: CryptoRng + RngCore,
{
    const MESSAGE: &[u8] = b"pqc-rs signature agility evaluation";
    const CONTEXT: &[u8] = b"paper-evaluation";

    let (public_key, secret_key) = scheme.keygen(rng)?;

    let signature = scheme.sign(&secret_key, MESSAGE, CONTEXT, rng)?;

    scheme.verify(&public_key, MESSAGE, CONTEXT, &signature)
}

#[test]
fn same_application_workflow_supports_ml_dsa() {
    let scheme = MlDsa::new(MlDsaParameterSet::MlDsa65);
    let mut rng = TestRng(0x1234_5678_9abc_def0);

    exercise_signature_scheme(&scheme, &mut rng).unwrap();
}

#[test]
fn same_application_workflow_supports_slh_dsa() {
    let scheme = SlhDsa::new(SlhDsaParameterSet::Shake128f);
    let mut rng = TestRng(0x1234_5678_9abc_def0);

    exercise_signature_scheme(&scheme, &mut rng).unwrap();
}

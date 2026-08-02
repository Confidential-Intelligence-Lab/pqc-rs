//! Execute supported NIST ACVP FIPS 205 external Pure SLH-DSA SigGen vectors.

use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

use pqc_slh_dsa::{SlhDsa, SlhDsaParameterSet, SlhDsaPrivateKey};
use pqc_test_harness::slhdsa_acvp::{
    siggen::{self, SigGenExpectedCase},
    AcvpParameterSet, PreHashMode, SignatureInterface,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

fn main() {
    if let Err(error) = run() {
        eprintln!("SLH-DSA ACVP external-pure SigGen failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().skip(1).collect();

    let root = arguments
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(repository_root);

    let limit = arguments
        .get(1)
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|error| format!("invalid case limit: {error}"))
        })
        .transpose()?;

    let vector_root = root.join("vectors/nist-acvp/slhdsa-siggen");

    let prompt = siggen::parse_prompt(&read(&vector_root.join("prompt.json"))?)
        .map_err(|error| error.to_string())?;

    let expected = siggen::parse_expected(&read(&vector_root.join("expectedResults.json"))?)
        .map_err(|error| error.to_string())?;

    if prompt.vs_id != expected.vs_id {
        return Err(format!(
            "vector-set identifier mismatch: prompt={} expected={}",
            prompt.vs_id, expected.vs_id
        ));
    }

    let expected_cases = expected
        .test_groups
        .iter()
        .flat_map(|group| {
            group
                .tests
                .iter()
                .map(move |case| ((group.tg_id, case.tc_id), case))
        })
        .collect::<BTreeMap<_, _>>();

    let supported_groups = prompt
        .test_groups
        .iter()
        .filter(|group| {
            group.signature_interface == SignatureInterface::External
                && group.pre_hash == Some(PreHashMode::Pure)
        })
        .collect::<Vec<_>>();

    let available = supported_groups
        .iter()
        .map(|group| group.tests.len())
        .sum::<usize>();

    let selected = limit.unwrap_or(available).min(available);

    let mut executed = 0_usize;
    let mut deterministic_cases = 0_usize;
    let mut hedged_cases = 0_usize;

    for group in supported_groups {
        let parameter_set = parameter_set(group.parameter_set);
        let implementation = SlhDsa::new(parameter_set);

        for case in &group.tests {
            if executed == selected {
                break;
            }

            let expected_case =
                expected_cases
                    .get(&(group.tg_id, case.tc_id))
                    .ok_or_else(|| {
                        format!(
                            "missing expected result for tgId={} tcId={}",
                            group.tg_id, case.tc_id
                        )
                    })?;

            execute_case(
                &implementation,
                parameter_set,
                group.tg_id,
                case.tc_id,
                group.deterministic,
                &case.sk,
                &case.message,
                case.context.as_deref(),
                case.additional_randomness.as_deref(),
                expected_case,
            )?;

            if group.deterministic {
                deterministic_cases += 1;
            } else {
                hedged_cases += 1;
            }

            executed += 1;
        }

        if executed == selected {
            break;
        }
    }

    println!("NIST ACVP FIPS 205 external Pure SLH-DSA SigGen");
    println!("vector set: {}", prompt.vs_id);
    println!("available supported cases: {available}");
    println!("executed cases: {executed}");
    println!("deterministic cases: {deterministic_cases}");
    println!("hedged cases: {hedged_cases}");
    println!("passed cases: {executed}");

    if executed != selected {
        return Err("SLH-DSA ACVP SigGen validation incomplete".to_owned());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_case(
    implementation: &SlhDsa,
    parameter_set: SlhDsaParameterSet,
    tg_id: u64,
    tc_id: u64,
    deterministic: bool,
    private_key_hex: &str,
    message_hex: &str,
    context_hex: Option<&str>,
    additional_randomness_hex: Option<&str>,
    expected: &SigGenExpectedCase,
) -> Result<(), String> {
    let private_key_bytes = decode_hex("sk", private_key_hex)?;
    let message = decode_hex("message", message_hex)?;

    let context = context_hex
        .map(|encoded| decode_hex("context", encoded))
        .transpose()?
        .unwrap_or_default();

    let private_key = SlhDsaPrivateKey::from_bytes(parameter_set, &private_key_bytes)
        .map_err(|error| format!("tgId={tg_id} tcId={tc_id}: invalid private key: {error}"))?;

    let signature = if deterministic {
        if additional_randomness_hex.is_some() {
            return Err(format!(
                "tgId={tg_id} tcId={tc_id}: deterministic case \
                 unexpectedly supplied additionalRandomness"
            ));
        }

        implementation
            .sign_deterministic(&private_key, &message, &context)
            .map_err(|error| {
                format!(
                    "tgId={tg_id} tcId={tc_id}: deterministic signing failed: \
                     {error}"
                )
            })?
    } else {
        let randomness_hex = additional_randomness_hex.ok_or_else(|| {
            format!(
                "tgId={tg_id} tcId={tc_id}: hedged case omitted \
                 additionalRandomness"
            )
        })?;

        let randomness = decode_hex("additionalRandomness", randomness_hex)?;

        let expected_randomness_bytes = parameter_set.parameters().n;

        if randomness.len() != expected_randomness_bytes {
            return Err(format!(
                "tgId={tg_id} tcId={tc_id}: additionalRandomness has {} \
                 bytes, expected {}",
                randomness.len(),
                expected_randomness_bytes
            ));
        }

        let mut rng = FixedBytesRng::new(randomness);

        implementation
            .sign_hedged(&private_key, &message, &context, &mut rng)
            .map_err(|error| format!("tgId={tg_id} tcId={tc_id}: hedged signing failed: {error}"))?
    };

    let expected_signature = decode_hex("signature", &expected.signature)?;

    compare(tg_id, tc_id, signature.as_bytes(), &expected_signature)
}

fn compare(tg_id: u64, tc_id: u64, actual: &[u8], expected: &[u8]) -> Result<(), String> {
    if actual == expected {
        return Ok(());
    }

    let first_difference = actual
        .iter()
        .zip(expected)
        .position(|(left, right)| left != right);

    Err(format!(
        "tgId={tg_id} tcId={tc_id}: signature mismatch; \
         actual_len={} expected_len={} first_difference={first_difference:?}",
        actual.len(),
        expected.len()
    ))
}

fn decode_hex(name: &str, encoded: &str) -> Result<Vec<u8>, String> {
    hex::decode(encoded).map_err(|error| format!("invalid hexadecimal {name}: {error}"))
}

const fn parameter_set(parameter_set: AcvpParameterSet) -> SlhDsaParameterSet {
    match parameter_set {
        AcvpParameterSet::Sha2_128s => SlhDsaParameterSet::Sha2_128s,
        AcvpParameterSet::Sha2_128f => SlhDsaParameterSet::Sha2_128f,
        AcvpParameterSet::Sha2_192s => SlhDsaParameterSet::Sha2_192s,
        AcvpParameterSet::Sha2_192f => SlhDsaParameterSet::Sha2_192f,
        AcvpParameterSet::Sha2_256s => SlhDsaParameterSet::Sha2_256s,
        AcvpParameterSet::Sha2_256f => SlhDsaParameterSet::Sha2_256f,
        AcvpParameterSet::Shake128s => SlhDsaParameterSet::Shake128s,
        AcvpParameterSet::Shake128f => SlhDsaParameterSet::Shake128f,
        AcvpParameterSet::Shake192s => SlhDsaParameterSet::Shake192s,
        AcvpParameterSet::Shake192f => SlhDsaParameterSet::Shake192f,
        AcvpParameterSet::Shake256s => SlhDsaParameterSet::Shake256s,
        AcvpParameterSet::Shake256f => SlhDsaParameterSet::Shake256f,
    }
}

struct FixedBytesRng {
    bytes: Vec<u8>,
    offset: usize,
}

impl FixedBytesRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }

    fn copy_into(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        let end = self
            .offset
            .checked_add(destination.len())
            .ok_or_else(rng_error)?;

        let source = self.bytes.get(self.offset..end).ok_or_else(rng_error)?;

        destination.copy_from_slice(source);
        self.offset = end;

        Ok(())
    }
}

impl RngCore for FixedBytesRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];

        self.copy_into(&mut bytes)
            .expect("ACVP fixed RNG exhausted");

        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];

        self.copy_into(&mut bytes)
            .expect("ACVP fixed RNG exhausted");

        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.copy_into(destination)
            .expect("ACVP fixed RNG exhausted");
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.copy_into(destination)
    }
}

impl CryptoRng for FixedBytesRng {}

fn rng_error() -> RandError {
    RandError::from(core::num::NonZeroU32::new(1).expect("ACVP RNG error code is nonzero"))
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

//! Execute NIST ACVP FIPS 205 SLH-DSA key-generation vectors.

use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

use pqc_slh_dsa::{SlhDsa, SlhDsaKeyGenSeed, SlhDsaParameterSet};
use pqc_test_harness::slhdsa_acvp::{
    keygen::{self, KeyGenExpectedCase},
    AcvpParameterSet,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("SLH-DSA ACVP KeyGen failed: {error}");
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

    let vector_root = root.join("vectors/nist-acvp/slhdsa-keygen");
    let prompt_path = vector_root.join("prompt.json");
    let expected_path = vector_root.join("expectedResults.json");

    let prompt = keygen::parse_prompt(&read(&prompt_path)?).map_err(|error| error.to_string())?;

    let expected =
        keygen::parse_expected(&read(&expected_path)?).map_err(|error| error.to_string())?;

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

    let available = prompt
        .test_groups
        .iter()
        .map(|group| group.tests.len())
        .sum::<usize>();

    let selected = limit.unwrap_or(available).min(available);

    let mut executed = 0_usize;

    for group in &prompt.test_groups {
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
                &case.sk_seed,
                &case.sk_prf,
                &case.pk_seed,
                expected_case,
            )?;

            executed += 1;
        }

        if executed == selected {
            break;
        }
    }

    println!("NIST ACVP FIPS 205 SLH-DSA KeyGen");
    println!("vector set: {}", prompt.vs_id);
    println!("available cases: {available}");
    println!("executed cases: {executed}");
    println!("passed cases: {executed}");

    if executed != selected {
        return Err("SLH-DSA ACVP KeyGen validation incomplete".to_owned());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_case(
    implementation: &SlhDsa,
    parameter_set: SlhDsaParameterSet,
    tg_id: u64,
    tc_id: u64,
    sk_seed_hex: &str,
    sk_prf_hex: &str,
    pk_seed_hex: &str,
    expected: &KeyGenExpectedCase,
) -> Result<(), String> {
    let sk_seed = decode_hex("skSeed", sk_seed_hex)?;
    let sk_prf = decode_hex("skPrf", sk_prf_hex)?;
    let pk_seed = decode_hex("pkSeed", pk_seed_hex)?;

    let parameters = parameter_set.parameters();

    for (name, component) in [
        ("skSeed", sk_seed.as_slice()),
        ("skPrf", sk_prf.as_slice()),
        ("pkSeed", pk_seed.as_slice()),
    ] {
        if component.len() != parameters.n {
            return Err(format!(
                "tgId={tg_id} tcId={tc_id}: {name} has {} bytes, expected {}",
                component.len(),
                parameters.n
            ));
        }
    }

    let mut seed_bytes = Vec::with_capacity(parameters.keygen_seed_bytes);
    seed_bytes.extend_from_slice(&sk_seed);
    seed_bytes.extend_from_slice(&sk_prf);
    seed_bytes.extend_from_slice(&pk_seed);

    let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes).map_err(|error| {
        format!("tgId={tg_id} tcId={tc_id}: invalid key-generation seed: {error}")
    })?;

    let key_pair = implementation
        .keygen_from_seed(&seed)
        .map_err(|error| format!("tgId={tg_id} tcId={tc_id}: key generation failed: {error}"))?;

    let expected_pk = decode_hex("pk", &expected.pk)?;
    let expected_sk = decode_hex("sk", &expected.sk)?;

    compare(
        tg_id,
        tc_id,
        "public key",
        key_pair.public_key().as_bytes(),
        &expected_pk,
    )?;

    compare(
        tg_id,
        tc_id,
        "private key",
        key_pair.private_key().as_bytes(),
        &expected_sk,
    )?;

    Ok(())
}

fn compare(
    tg_id: u64,
    tc_id: u64,
    object: &str,
    actual: &[u8],
    expected: &[u8],
) -> Result<(), String> {
    if actual == expected {
        return Ok(());
    }

    let first_difference = actual
        .iter()
        .zip(expected)
        .position(|(left, right)| left != right);

    Err(format!(
        "tgId={tg_id} tcId={tc_id}: {object} mismatch; \
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

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

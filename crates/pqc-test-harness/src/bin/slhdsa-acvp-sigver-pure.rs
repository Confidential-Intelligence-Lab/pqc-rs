//! Execute supported NIST ACVP FIPS 205 external Pure SLH-DSA SigVer vectors.

use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

use pqc_slh_dsa::{SlhDsa, SlhDsaParameterSet, SlhDsaPublicKey, SlhDsaSignature};
use pqc_test_harness::slhdsa_acvp::{
    sigver::{self, SigVerExpectedCase},
    AcvpParameterSet, PreHashMode, SignatureInterface,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("SLH-DSA ACVP external-pure SigVer failed: {error}");
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

    let vector_root = root.join("vectors/nist-acvp/slhdsa-sigver");

    let prompt = sigver::parse_prompt(&read(&vector_root.join("prompt.json"))?)
        .map_err(|error| error.to_string())?;

    let expected = sigver::parse_expected(&read(&vector_root.join("expectedResults.json"))?)
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
    let mut expected_valid = 0_usize;
    let mut expected_invalid = 0_usize;

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
                &case.pk,
                &case.message,
                case.context.as_deref(),
                &case.signature,
                expected_case,
            )?;

            if expected_case.test_passed {
                expected_valid += 1;
            } else {
                expected_invalid += 1;
            }

            executed += 1;
        }

        if executed == selected {
            break;
        }
    }

    println!("NIST ACVP FIPS 205 external Pure SLH-DSA SigVer");
    println!("vector set: {}", prompt.vs_id);
    println!("available supported cases: {available}");
    println!("executed cases: {executed}");
    println!("expected valid cases: {expected_valid}");
    println!("expected invalid cases: {expected_invalid}");
    println!("matched cases: {executed}");

    if executed != selected {
        return Err("SLH-DSA ACVP SigVer validation incomplete".to_owned());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_case(
    implementation: &SlhDsa,
    parameter_set: SlhDsaParameterSet,
    tg_id: u64,
    tc_id: u64,
    public_key_hex: &str,
    message_hex: &str,
    context_hex: Option<&str>,
    signature_hex: &str,
    expected: &SigVerExpectedCase,
) -> Result<(), String> {
    let public_key_bytes = decode_hex("pk", public_key_hex)?;
    let message = decode_hex("message", message_hex)?;
    let signature_bytes = decode_hex("signature", signature_hex)?;

    let context = context_hex
        .map(|encoded| decode_hex("context", encoded))
        .transpose()?
        .unwrap_or_default();

    let actual = verify_case(
        implementation,
        parameter_set,
        &public_key_bytes,
        &message,
        &context,
        &signature_bytes,
    )?;

    if actual == expected.test_passed {
        return Ok(());
    }

    Err(format!(
        "tgId={tg_id} tcId={tc_id}: verification mismatch; \
         actual={actual} expected={}",
        expected.test_passed
    ))
}

fn verify_case(
    implementation: &SlhDsa,
    parameter_set: SlhDsaParameterSet,
    public_key_bytes: &[u8],
    message: &[u8],
    context: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, String> {
    let public_key = match SlhDsaPublicKey::from_bytes(parameter_set, public_key_bytes) {
        Ok(public_key) => public_key,
        Err(_) => return Ok(false),
    };

    let signature = match SlhDsaSignature::from_bytes(parameter_set, signature_bytes) {
        Ok(signature) => signature,
        Err(_) => return Ok(false),
    };

    implementation
        .verify(&public_key, message, context, &signature)
        .map_err(|error| format!("signature verification failed: {error}"))
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

use pqc_ml_dsa::keygen::keygen_internal;
use pqc_ml_dsa::params::MlDsaParameterSet;
use pqc_ml_dsa::signature::sign_internal;
use pqc_ml_dsa::verification::verify_internal;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

fn main() {
    let mut total = 0_usize;
    let mut passed = 0_usize;

    println!("PQC-rs ML-DSA Stage 9D validation");
    println!();

    for parameter_set in parameter_sets() {
        let mut parameter_total = 0_usize;
        let mut parameter_passed = 0_usize;

        for case_id in 0_u8..8 {
            total += 1;
            parameter_total += 1;

            let seed = deterministic_bytes::<32>(parameter_tag(parameter_set), case_id);
            let randomness =
                deterministic_bytes::<32>(parameter_tag(parameter_set).wrapping_add(1), case_id);
            let message = deterministic_message(case_id);
            let context = deterministic_context(case_id);

            let result = run_case(parameter_set, &seed, &randomness, &message, &context);

            match result {
                Ok(fingerprint) => {
                    passed += 1;
                    parameter_passed += 1;
                    println!(
                        "  {} case={case_id:02} PASS fingerprint={fingerprint}",
                        parameter_set.name(),
                    );
                }
                Err(error) => {
                    println!("  {} case={case_id:02} FAIL {error}", parameter_set.name(),);
                }
            }
        }

        println!(
            "{} total={} passed={} failed={}",
            parameter_set.name(),
            parameter_total,
            parameter_passed,
            parameter_total - parameter_passed,
        );
        println!();
    }

    println!("total:  {total}");
    println!("passed: {passed}");
    println!("failed: {}", total - passed);

    if total != passed {
        std::process::exit(1);
    }
}

fn run_case(
    parameter_set: MlDsaParameterSet,
    seed: &[u8; 32],
    randomness: &[u8; 32],
    message: &[u8],
    context: &[u8],
) -> Result<String, String> {
    let key_pair = keygen_internal(parameter_set, seed).map_err(|error| format!("{error:?}"))?;
    let signature = sign_internal(
        parameter_set,
        key_pair.private_key(),
        message,
        context,
        randomness,
    )
    .map_err(|error| format!("{error:?}"))?;

    let valid = verify_internal(
        parameter_set,
        key_pair.public_key(),
        message,
        context,
        &signature,
    )
    .map_err(|error| format!("{error:?}"))?;

    if !valid {
        return Err("self-verification returned false".to_owned());
    }

    Ok(fingerprint(
        key_pair.public_key(),
        key_pair.private_key(),
        &signature,
    ))
}

fn fingerprint(public_key: &[u8], private_key: &[u8], signature: &[u8]) -> String {
    let mut hasher = Shake256::default();
    hasher.update(public_key);
    hasher.update(private_key);
    hasher.update(signature);
    let mut reader = hasher.finalize_xof();
    let mut digest = [0_u8; 16];
    reader.read(&mut digest);
    hex(&digest)
}

fn deterministic_bytes<const LENGTH: usize>(domain: u8, case_id: u8) -> [u8; LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(b"pqc-rs-stage9d6");
    hasher.update(&[domain, case_id]);
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; LENGTH];
    reader.read(&mut output);
    output
}

fn deterministic_message(case_id: u8) -> Vec<u8> {
    let length = match case_id {
        0 => 0,
        1 => 1,
        2 => 31,
        3 => 32,
        4 => 64,
        5 => 255,
        6 => 256,
        _ => 1024,
    };

    deterministic_vec(0xA0, case_id, length)
}

fn deterministic_context(case_id: u8) -> Vec<u8> {
    let length = match case_id {
        0 | 1 => 0,
        2 => 1,
        3 => 8,
        4 => 32,
        5 => 127,
        6 => 254,
        _ => 255,
    };

    deterministic_vec(0xC0, case_id, length)
}

fn deterministic_vec(domain: u8, case_id: u8, length: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(b"pqc-rs-stage9d6");
    hasher.update(&[domain, case_id]);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0_u8; length];
    reader.read(&mut output);
    output
}

fn parameter_sets() -> [MlDsaParameterSet; 3] {
    [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ]
}

fn parameter_tag(parameter_set: MlDsaParameterSet) -> u8 {
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => 44,
        MlDsaParameterSet::MlDsa65 => 65,
        MlDsaParameterSet::MlDsa87 => 87,
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }

    output
}

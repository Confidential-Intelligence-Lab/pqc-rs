use pqc_haetae::packing::{public_key_bytes, secret_key_bytes};
use pqc_haetae::params::ParameterSet;
use pqc_haetae::signing_init::derive_signing_initialization;
use std::fs;
use std::path::PathBuf;

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).expect("hex UTF-8");
            u8::from_str_radix(s, 16).expect("valid hex")
        })
        .collect()
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let (actual_name, value) = line.split_once('=').expect("fixture field");
    assert_eq!(actual_name, name);
    value
}

fn run_mode(mode_number: usize, mode: ParameterSet) {
    let root = PathBuf::from(
        std::env::var("HAETAE_SIGNING_INITIALIZATION_PARITY_DIR")
            .expect("HAETAE_SIGNING_INITIALIZATION_PARITY_DIR must be set"),
    );
    let path = root.join(format!("signing_init_mode{mode_number}.txt"));
    let content = fs::read_to_string(path).expect("reference fixture");
    let lines: Vec<&str> = content.lines().collect();

    let pk_len = public_key_bytes(mode);
    let sk_len = secret_key_bytes(mode);

    assert_eq!(
        field(lines[0], "PUBLICKEYBYTES").parse::<usize>().unwrap(),
        pk_len
    );
    assert_eq!(
        field(lines[1], "SECRETKEYBYTES").parse::<usize>().unwrap(),
        sk_len
    );
    assert_eq!(lines.len(), 152);

    let mut compared = 0_usize;

    for index in 0..15 {
        let case = index / 3;
        let scenario = index % 3;
        let block = &lines[2 + index * 10..2 + (index + 1) * 10];

        assert_eq!(field(block[0], "CASE"), case.to_string());
        assert_eq!(field(block[1], "SCENARIO"), scenario.to_string());
        assert_eq!(field(block[9], "END_SCENARIO"), scenario.to_string());

        let seed = decode_hex(field(block[2], "SEED"));
        let pk = decode_hex(field(block[3], "PK"));
        let message = decode_hex(field(block[4], "MESSAGE"));
        let context = decode_hex(field(block[5], "CONTEXT"));
        let rnd = decode_hex(field(block[6], "RND"));
        let expected_mu = decode_hex(field(block[7], "MU"));
        let expected_sign_seed = decode_hex(field(block[8], "SIGN_SEED"));

        assert_eq!(seed.len(), 32);
        assert_eq!(pk.len(), pk_len);
        assert_eq!(rnd.len(), 32);

        let keypair_path = PathBuf::from(
            std::env::var("HAETAE_KEYGEN_KEYPAIR_PARITY_DIR")
                .expect("HAETAE_KEYGEN_KEYPAIR_PARITY_DIR must be set"),
        )
        .join(format!("keypair_mode{mode_number}.txt"));

        let keypair_text = fs::read_to_string(keypair_path).expect("keypair fixture");
        let keypair_lines: Vec<&str> = keypair_text.lines().collect();
        let key_block = &keypair_lines[2 + case * 5..2 + (case + 1) * 5];

        assert_eq!(field(key_block[0], "CASE"), case.to_string());
        assert_eq!(field(key_block[4], "END_CASE"), case.to_string());
        assert_eq!(decode_hex(field(key_block[1], "SEED")), seed);
        assert_eq!(decode_hex(field(key_block[2], "PK")), pk);

        let sk = decode_hex(field(key_block[3], "SK"));
        assert_eq!(sk.len(), sk_len);
        assert_eq!(&sk[..pk_len], pk.as_slice());

        let randomness: [u8; 32] = rnd.try_into().expect("32-byte randomness");

        let actual = derive_signing_initialization(&sk, &message, &context, &randomness, mode)
            .expect("valid signing initialization");

        assert_eq!(
            actual.mu.as_slice(),
            expected_mu.as_slice(),
            "MU mismatch MODE={mode_number} CASE={case} SCENARIO={scenario}"
        );
        assert_eq!(
            actual.signing_seed.as_slice(),
            expected_sign_seed.as_slice(),
            "SIGN_SEED mismatch MODE={mode_number} CASE={case} SCENARIO={scenario}"
        );

        compared += 128;

        println!(
            "MODE={mode_number} CASE={case} SCENARIO={scenario} \
             MU=PASS SIGN_SEED=PASS"
        );
    }

    assert_eq!(compared, 1920);
    println!("MODE={mode_number} VECTORS=15 EXACT_HASH_BYTES={compared} STATUS=PASS");
}

#[test]
fn signing_initialization_mode2() {
    run_mode(2, ParameterSet::Haetae2);
}

#[test]
fn signing_initialization_mode3() {
    run_mode(3, ParameterSet::Haetae3);
}

#[test]
fn signing_initialization_mode5() {
    run_mode(5, ParameterSet::Haetae5);
}

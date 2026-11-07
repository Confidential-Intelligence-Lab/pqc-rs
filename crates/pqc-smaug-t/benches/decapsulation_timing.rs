use pqc_rs_smaug_t::kem;
use pqc_rs_smaug_t::{Parameters, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};
use std::hint::black_box;
use std::io::{self, Write};
use std::time::Instant;

fn parameters(name: &str) -> Parameters {
    match name {
        "mode1" => SMAUG_T128,
        "mode3" => SMAUG_T192,
        "mode5" => SMAUG_T256,
        "modet" => TIMER,
        _ => panic!("unsupported mode: {name}"),
    }
}

fn next_random(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    assert!(
        args.len() == 4,
        "usage: decapsulation_timing MODE SAMPLES WARMUPS"
    );

    let mode = &args[1];
    let samples: usize = args[2].parse().expect("samples");
    let warmups: usize = args[3].parse().expect("warmups");

    assert!(samples > 0);
    assert!(samples <= 1_000_000);

    let params = parameters(mode);

    let seed = [0x42u8; 32];
    let auxiliary = [0xa5u8; 32];
    let message = vec![0x39u8; if mode == "modet" { 16 } else { 32 }];

    let (public_key, secret_key) = kem::keypair(&seed, &auxiliary, &params).expect("keypair");

    let (valid_ciphertext, expected_secret) =
        kem::encapsulate_deterministic(&public_key, &message, &params).expect("encapsulation");

    let mut modified_ciphertext = valid_ciphertext.clone();
    assert!(!modified_ciphertext.is_empty());
    modified_ciphertext[0] ^= 1;

    let valid_result =
        kem::decapsulate(&valid_ciphertext, &secret_key, &params).expect("valid decapsulation");

    assert_eq!(valid_result, expected_secret);

    let modified_result = kem::decapsulate(&modified_ciphertext, &secret_key, &params)
        .expect("modified decapsulation");

    assert_ne!(
        modified_result, expected_secret,
        "modified ciphertext did not change shared secret"
    );

    let mut state = 0x6a09e667f3bcc909u64;

    for _ in 0..warmups {
        let class = (next_random(&mut state) & 1) as usize;
        let ciphertext = if class == 0 {
            &valid_ciphertext
        } else {
            &modified_ciphertext
        };

        black_box(
            kem::decapsulate(
                black_box(ciphertext),
                black_box(&secret_key),
                black_box(&params),
            )
            .expect("warmup decapsulation"),
        );
    }

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    writeln!(out, "mode,class,round,elapsed_ns").unwrap();

    for round in 0..samples {
        let first_class = (next_random(&mut state) & 1) as usize;

        for position in 0..2 {
            let class = first_class ^ position;

            let ciphertext = if class == 0 {
                &valid_ciphertext
            } else {
                &modified_ciphertext
            };

            let start = Instant::now();

            let result = kem::decapsulate(
                black_box(ciphertext),
                black_box(&secret_key),
                black_box(&params),
            )
            .expect("timed decapsulation");

            let elapsed = start.elapsed().as_nanos();

            black_box(result);

            writeln!(out, "{mode},{class},{round},{elapsed}").unwrap();
        }
    }

    out.flush().unwrap();
}

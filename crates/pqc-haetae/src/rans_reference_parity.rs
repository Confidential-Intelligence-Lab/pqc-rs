// SPDX-License-Identifier: MIT

use crate::rans::{
    decode, encode, Symbol, MODE2_H, MODE2_HB_Z1, MODE3_H, MODE3_HB_Z1, MODE5_H, MODE5_HB_Z1,
};

fn hex_decode(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn table(mode: u8, kind: &str) -> (&'static [Symbol], i32, i32) {
    match (mode, kind) {
        (2, "H") => (&MODE2_H, 6, 239),
        (3, "H") => (&MODE3_H, 8, 235),
        (5, "H") => (&MODE5_H, 16, 471),
        (2, "HB_Z1") => (&MODE2_HB_Z1, 6, 0),
        (3, "HB_Z1") => (&MODE3_HB_Z1, 8, 0),
        (5, "HB_Z1") => (&MODE5_HB_Z1, 9, 0),
        _ => panic!("unknown HAETAE mode or encoding kind"),
    }
}

fn run_mode(mode: u8) {
    let base = std::env::var("HAETAE_RANS_PARITY_DIR")
        .expect("HAETAE_RANS_PARITY_DIR must point to the C oracle fixtures");

    let path = std::path::Path::new(&base).join(format!("rans_mode{mode}.txt"));

    let input = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = input.lines().collect();

    assert_eq!(lines.len(), 50);

    for record in lines.chunks_exact(5) {
        let header = record[0];
        let values = record[1].strip_prefix("VALUES=").unwrap();
        let encoded = record[2].strip_prefix("ENCODED=").unwrap();
        let length = record[3].strip_prefix("LENGTH=").unwrap();

        assert_eq!(record[4], "END");

        let mut fields = header.split_whitespace();

        let fixture_mode = fields
            .next()
            .unwrap()
            .strip_prefix("MODE=")
            .unwrap()
            .parse::<u8>()
            .unwrap();

        let kind = fields.next().unwrap().strip_prefix("KIND=").unwrap();

        let pattern = fields
            .next()
            .unwrap()
            .strip_prefix("PATTERN=")
            .unwrap()
            .parse::<usize>()
            .unwrap();

        let count = fields
            .next()
            .unwrap()
            .strip_prefix("COUNT=")
            .unwrap()
            .parse::<usize>()
            .unwrap();

        assert_eq!(fixture_mode, mode);
        assert!(pattern < 5);

        let coefficients: Vec<i32> = values
            .split(',')
            .map(|value| value.parse::<i32>().unwrap())
            .collect();

        assert_eq!(coefficients.len(), count);

        let (distribution, offset, hint_offset) = table(mode, kind);

        let symbols: Vec<u16> = coefficients
            .iter()
            .map(|&coefficient| {
                let symbol = if kind == "H" {
                    if coefficient > offset + hint_offset {
                        coefficient - hint_offset
                    } else {
                        assert!(coefficient <= offset, "invalid hint coefficient");
                        coefficient
                    }
                } else {
                    coefficient + offset
                };

                assert!(symbol >= 0);
                assert!((symbol as usize) < distribution.len());
                symbol as u16
            })
            .collect();

        let reference = hex_decode(encoded);
        assert_eq!(reference.len(), length.parse::<usize>().unwrap());

        let rust_encoded = encode(&symbols, distribution, count).unwrap();

        assert_eq!(
            rust_encoded, reference,
            "C/Rust encoding mismatch: mode={mode}, kind={kind}, pattern={pattern}"
        );

        let rust_decoded = decode(&reference, distribution, count).unwrap();

        assert_eq!(
            rust_decoded, symbols,
            "C/Rust decoding mismatch: mode={mode}, kind={kind}, pattern={pattern}"
        );

        println!(
            "MODE={mode} KIND={kind} PATTERN={pattern} \
             ENCODED_BYTES={} PARITY=PASS",
            reference.len()
        );
    }
}

#[test]
fn rans_reference_mode2() {
    run_mode(2);
}

#[test]
fn rans_reference_mode3() {
    run_mode(3);
}

#[test]
fn rans_reference_mode5() {
    run_mode(5);
}

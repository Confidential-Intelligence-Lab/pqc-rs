#![no_main]

use libfuzzer_sys::fuzz_target;
use pqc_rs_smaug_t::encoding::{pack_secret, unpack_secret, SECRET_POLY_BYTES};

const PREFIX: &[u8; 4] = b"SMTF";

fn mutate(bytes: &mut Vec<u8>, offset: usize, operation: u8, value: u8) {
    match operation % 4 {
        0 if !bytes.is_empty() => {
            let index = offset % bytes.len();
            bytes[index] ^= 1u8 << (value % 8);
        }
        1 if !bytes.is_empty() => {
            let index = offset % bytes.len();
            bytes[index] = value;
        }
        2 if !bytes.is_empty() => {
            let index = offset % bytes.len();
            bytes.remove(index);
        }
        3 => {
            let index = offset % (bytes.len() + 1);
            bytes.insert(index, value);
        }
        _ => {}
    }
}

fn check(data: &[u8]) {
    let first = unpack_secret(data);
    let second = unpack_secret(data);
    assert_eq!(first, second);

    if let Ok(coefficients) = first {
        let encoded = pack_secret(&coefficients).expect("decoded coefficients must encode");
        assert_eq!(encoded.as_slice(), data);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() >= 10 && &data[..4] == PREFIX {
        let mode = usize::from(data[4]) % 4;
        let region = usize::from(data[5]) % 4;
        let offset = usize::from(u16::from_le_bytes([data[6], data[7]]));
        let operation = data[8];
        let value = data[9];

        let coefficients = std::array::from_fn(|i| match (i + mode + region) % 3 {
            0 => -1i16,
            1 => 0i16,
            _ => 1i16,
        });

        let canonical = pack_secret(&coefficients).unwrap();
        assert_eq!(unpack_secret(&canonical), Ok(coefficients));

        let mut encoded = canonical.to_vec();
        mutate(&mut encoded, offset, operation, value);
        check(&encoded);
    } else {
        check(data);

        let mut fixed = [0u8; SECRET_POLY_BYTES];
        let count = data.len().min(fixed.len());
        fixed[..count].copy_from_slice(&data[..count]);
        check(&fixed);
    }
});

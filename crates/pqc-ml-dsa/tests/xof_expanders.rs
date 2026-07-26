#![cfg(feature = "internal-api")]

use pqc_ml_dsa::xof::{
    expand_a_bytes, expand_mask_bytes, expand_s_bytes, ExpandAReader, ExpandMaskReader,
    ExpandSReader,
};

#[test]
fn expand_a_is_deterministic_and_domain_separated() {
    let rho = [0x11; 32];
    let mut a = [0u8; 256];
    let mut b = [0u8; 256];
    let mut c = [0u8; 256];

    expand_a_bytes(&rho, 3, 2, &mut a);
    expand_a_bytes(&rho, 3, 2, &mut b);
    expand_a_bytes(&rho, 2, 3, &mut c);

    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn expand_s_is_deterministic_and_nonce_separated() {
    let seed = [0x22; 64];
    let mut a = [0u8; 192];
    let mut b = [0u8; 192];
    let mut c = [0u8; 192];

    expand_s_bytes(&seed, 7, &mut a);
    expand_s_bytes(&seed, 7, &mut b);
    expand_s_bytes(&seed, 8, &mut c);

    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn expand_mask_is_deterministic_and_nonce_separated() {
    let seed = [0x33; 64];
    let mut a = [0u8; 256];
    let mut b = [0u8; 256];
    let mut c = [0u8; 256];

    expand_mask_bytes(&seed, 12, &mut a);
    expand_mask_bytes(&seed, 12, &mut b);
    expand_mask_bytes(&seed, 13, &mut c);

    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn streaming_matches_one_shot() {
    let rho = [0x44; 32];
    let mut fixed = [0u8; 300];
    let mut streamed = [0u8; 300];

    expand_a_bytes(&rho, 4, 1, &mut fixed);
    let mut reader = ExpandAReader::new(&rho, 4, 1);
    reader.read(&mut streamed[..73]);
    reader.read(&mut streamed[73..]);
    assert_eq!(fixed, streamed);

    let seed = [0x55; 64];
    expand_s_bytes(&seed, 0x1234, &mut fixed);
    let mut reader = ExpandSReader::new(&seed, 0x1234);
    reader.read(&mut streamed[..99]);
    reader.read(&mut streamed[99..]);
    assert_eq!(fixed, streamed);

    expand_mask_bytes(&seed, 0xBEEF, &mut fixed);
    let mut reader = ExpandMaskReader::new(&seed, 0xBEEF);
    reader.read(&mut streamed[..127]);
    reader.read(&mut streamed[127..]);
    assert_eq!(fixed, streamed);
}

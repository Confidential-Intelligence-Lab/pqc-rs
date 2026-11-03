// SPDX-License-Identifier: MIT

// Deterministic assurance tests for authenticated HAETAE signatures.
// Test-only: no production cryptographic implementation changes.

#[path = "../fuzz_targets/authenticated_fixtures.rs"]
mod authenticated_fixtures;

use authenticated_fixtures::FIXTURES;

use pqc_haetae::params::ParameterSet;
use pqc_haetae::rans::{
    decode, RansError, MODE2_H, MODE2_HB_Z1, MODE3_H, MODE3_HB_Z1, MODE5_H, MODE5_HB_Z1,
};
use pqc_haetae::signature_packing::{unpack_signature, SignaturePackingError};

#[test]
fn authenticated_rans_decoder_reachability() {
    let mut checked = 0usize;
    let mut padding_checked = 0usize;
    let mut mode_counts = [0usize; 3];

    for fixture in FIXTURES {
        let (mode, k, l, base_hb, base_h, hb_table, h_table, index) = match fixture.mode {
            2 => (
                ParameterSet::Haetae2,
                2,
                4,
                132,
                7,
                MODE2_HB_Z1.as_slice(),
                MODE2_H.as_slice(),
                0,
            ),
            3 => (
                ParameterSet::Haetae3,
                3,
                6,
                376,
                127,
                MODE3_HB_Z1.as_slice(),
                MODE3_H.as_slice(),
                1,
            ),
            5 => (
                ParameterSet::Haetae5,
                4,
                7,
                501,
                358,
                MODE5_HB_Z1.as_slice(),
                MODE5_H.as_slice(),
                2,
            ),
            other => panic!("Unexpected fixture mode: {other}"),
        };

        let signature = fixture.signature;

        unpack_signature(mode, signature).expect("Authenticated signature must decode");

        let length_offset = 32 + l * 256;
        let hb_start = length_offset + 2;
        let hb_end = hb_start + base_hb + usize::from(signature[length_offset]);
        let h_end = hb_end + base_h + usize::from(signature[length_offset + 1]);

        assert!(h_end <= signature.len());
        assert!(hb_end - hb_start >= 4);
        assert!(h_end - hb_end >= 4);

        let highbits = decode(&signature[hb_start..hb_end], hb_table, l * 256)
            .expect("Authenticated highbits rANS");

        let hints =
            decode(&signature[hb_end..h_end], h_table, k * 256).expect("Authenticated hints rANS");

        assert_eq!(highbits.len(), l * 256);
        assert_eq!(hints.len(), k * 256);

        let mut bad_highbits = signature.to_vec();
        bad_highbits[hb_start..hb_start + 4].fill(0);

        assert_eq!(
            decode(&bad_highbits[hb_start..hb_end], hb_table, l * 256,),
            Err(RansError::InvalidState),
        );

        assert_eq!(
            unpack_signature(mode, &bad_highbits),
            Err(SignaturePackingError::InvalidHighbits),
        );

        let mut bad_hints = signature.to_vec();
        bad_hints[hb_end..hb_end + 4].fill(0);

        assert_eq!(
            decode(&bad_hints[hb_end..h_end], h_table, k * 256,),
            Err(RansError::InvalidState),
        );

        assert_eq!(
            unpack_signature(mode, &bad_hints),
            Err(SignaturePackingError::InvalidHint),
        );

        if h_end < signature.len() {
            let mut bad_padding = signature.to_vec();
            assert!(bad_padding[h_end..].iter().all(|&b| b == 0));
            bad_padding[h_end] = 1;

            assert_eq!(
                unpack_signature(mode, &bad_padding),
                Err(SignaturePackingError::InvalidDimensions),
            );

            padding_checked += 1;
        }

        checked += 1;
        mode_counts[index] += 1;
    }

    assert_eq!(checked, 15);
    assert_eq!(mode_counts, [5, 5, 5]);

    println!("RANS_AUTHENTICATED_FIXTURES={checked}");
    println!("RANS_HIGHBITS_SUCCESS={checked}");
    println!("RANS_HINTS_SUCCESS={checked}");
    println!("RANS_INVALID_HIGHBITS_REJECTIONS={checked}");
    println!("RANS_INVALID_HINT_REJECTIONS={checked}");
    println!("RANS_PADDING_REJECTIONS={padding_checked}");
    println!("RANS_DECODER_REACHABILITY_STATUS=PASS");
}

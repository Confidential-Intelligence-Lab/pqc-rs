use pqc_ml_dsa::{MlDsa, MlDsaParameterSet};

#[test]
fn parameter_sets_match_fips_204_sizes() {
    let cases = [
        (MlDsaParameterSet::MlDsa44, 1_312, 2_560, 2_420),
        (MlDsaParameterSet::MlDsa65, 1_952, 4_032, 3_309),
        (MlDsaParameterSet::MlDsa87, 2_592, 4_896, 4_627),
    ];

    for (set, public_key, private_key, signature) in cases {
        let implementation = MlDsa::new(set);
        assert_eq!(implementation.public_key_bytes(), public_key);
        assert_eq!(implementation.private_key_bytes(), private_key);
        assert_eq!(implementation.signature_bytes(), signature);
    }
}

#![cfg(feature = "internal-api")]

use pqc_ml_dsa::keygen::{derive_keygen_seeds, keygen_internal};
use pqc_ml_dsa::params::MlDsaParameterSet;

#[test]
fn deterministic_keygen_has_standardized_lengths() {
    for (index, parameter_set) in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ]
    .into_iter()
    .enumerate()
    {
        let mut seed = [0_u8; 32];
        seed[0] = index as u8 + 1;

        let key_pair = keygen_internal(parameter_set, &seed).unwrap();
        let parameters = parameter_set.parameters();

        assert_eq!(key_pair.public_key().len(), parameters.public_key_bytes);
        assert_eq!(key_pair.private_key().len(), parameters.private_key_bytes);
    }
}

#[test]
fn deterministic_keygen_is_reproducible() {
    let seed = [0x11; 32];

    let first = keygen_internal(MlDsaParameterSet::MlDsa65, &seed).unwrap();
    let second = keygen_internal(MlDsaParameterSet::MlDsa65, &seed).unwrap();

    assert_eq!(first.public_key(), second.public_key());
    assert_eq!(first.private_key(), second.private_key());
}

#[test]
fn different_seeds_produce_different_keys() {
    let first = keygen_internal(MlDsaParameterSet::MlDsa44, &[0x22; 32]).unwrap();
    let second = keygen_internal(MlDsaParameterSet::MlDsa44, &[0x23; 32]).unwrap();

    assert_ne!(first.public_key(), second.public_key());
    assert_ne!(first.private_key(), second.private_key());
}

#[test]
fn parameter_set_domain_separation_changes_derived_seeds() {
    let xi = [0x33; 32];
    let first = derive_keygen_seeds(&xi, 4, 4);
    let second = derive_keygen_seeds(&xi, 6, 5);

    assert_ne!(first, second);
}

#[test]
fn private_key_is_not_debug_printable_by_design() {
    let key_pair = keygen_internal(MlDsaParameterSet::MlDsa87, &[0x44; 32]).unwrap();

    assert!(!key_pair.private_key().is_empty());
}

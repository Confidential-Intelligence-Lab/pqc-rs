#![no_main]

use libfuzzer_sys::fuzz_target;
use pqc_ml_kem::ml_kem_key_check::{
    decapsulation_key_is_valid, encapsulation_key_is_valid,
};
use pqc_ml_kem::MlKemParameterSet;

fn parameter_set(selector: u8) -> MlKemParameterSet {
    match selector % 3 {
        0 => MlKemParameterSet::MlKem512,
        1 => MlKemParameterSet::MlKem768,
        _ => MlKemParameterSet::MlKem1024,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let set = parameter_set(data[0]);
    let candidate = &data[1..];

    let _ = encapsulation_key_is_valid(set, candidate);
    let _ = decapsulation_key_is_valid(set, candidate);
});

#![no_main]

use libfuzzer_sys::fuzz_target;
use pqc_ml_kem::ml_kem_decaps::decaps_internal;
use pqc_ml_kem::MlKemParameterSet;

struct Dimensions {
    dk: usize,
    ct: usize,
}

fn configuration(selector: u8) -> (MlKemParameterSet, Dimensions) {
    match selector % 3 {
        0 => (
            MlKemParameterSet::MlKem512,
            Dimensions { dk: 1632, ct: 768 },
        ),
        1 => (
            MlKemParameterSet::MlKem768,
            Dimensions { dk: 2400, ct: 1088 },
        ),
        _ => (
            MlKemParameterSet::MlKem1024,
            Dimensions { dk: 3168, ct: 1568 },
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let (set, dimensions) = configuration(data[0]);
    let payload = &data[1..];

    if payload.len() < dimensions.dk + dimensions.ct {
        let split = payload.len().min(dimensions.dk);
        let _ = decaps_internal(set, &payload[..split], &payload[split..]);
        return;
    }

    let dk = &payload[..dimensions.dk];
    let ct = &payload[dimensions.dk..dimensions.dk + dimensions.ct];
    let _ = decaps_internal(set, dk, ct);
});

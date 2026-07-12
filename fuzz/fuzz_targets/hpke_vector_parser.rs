#![no_main]

use libfuzzer_sys::fuzz_target;
use pqc_test_harness::hpke_pq_vectors::HpkePqVector;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Vec<HpkePqVector>>(data);
});

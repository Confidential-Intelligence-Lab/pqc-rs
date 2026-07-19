#![no_main]

use libfuzzer_sys::fuzz_target;
use pqc_ml_dsa::verification::verify_internal_message;
use pqc_ml_dsa::MlDsaParameterSet;

fn parameter_set(selector: u8) -> MlDsaParameterSet {
    match selector % 3 {
        0 => MlDsaParameterSet::MlDsa44,
        1 => MlDsaParameterSet::MlDsa65,
        _ => MlDsaParameterSet::MlDsa87,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let set = parameter_set(data[0]);
    let parameters = set.parameters();
    let payload = &data[1..];

    let public_key_end = payload.len().min(parameters.public_key_bytes);
    let signature_end = payload
        .len()
        .min(public_key_end.saturating_add(parameters.signature_bytes));

    let public_key = &payload[..public_key_end];
    let signature = &payload[public_key_end..signature_end];
    let message = &payload[signature_end..];

    let _ = verify_internal_message(set, public_key, message, signature);
});

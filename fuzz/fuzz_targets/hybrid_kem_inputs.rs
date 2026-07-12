#![no_main]

use libfuzzer_sys::fuzz_target;
use pqc_hpke::hybrid_kem::HybridKem;

fn kem(selector: u8) -> HybridKem {
    match selector % 3 {
        0 => HybridKem::MlKem768P256,
        1 => HybridKem::MlKem768X25519,
        _ => HybridKem::MlKem1024P384,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let kem = kem(data[0]);
    let payload = &data[1..];

    let key_pair = match kem.derive_key_pair(&[0x33; 64]) {
        Ok(value) => value,
        Err(_) => return,
    };

    let randomness_length = kem.randomness_length();
    let split = payload.len().min(randomness_length);
    let randomness = &payload[..split];
    let candidate_encapsulation = &payload[split..];

    let _ = kem.encapsulate_deterministic(
        &key_pair.public_key,
        randomness,
    );

    let _ = kem.decapsulate(
        &key_pair.private_seed,
        candidate_encapsulation,
    );
});

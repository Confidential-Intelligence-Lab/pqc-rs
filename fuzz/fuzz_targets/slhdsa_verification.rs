#![no_main]

use libfuzzer_sys::fuzz_target;

use pqc_slh_dsa::{SlhDsa, SlhDsaParameterSet, SlhDsaPublicKey, SlhDsaSignature};

fn parameter_set(selector: u8) -> SlhDsaParameterSet {
    match selector % 12 {
        0 => SlhDsaParameterSet::Sha2_128s,
        1 => SlhDsaParameterSet::Sha2_128f,
        2 => SlhDsaParameterSet::Sha2_192s,
        3 => SlhDsaParameterSet::Sha2_192f,
        4 => SlhDsaParameterSet::Sha2_256s,
        5 => SlhDsaParameterSet::Sha2_256f,
        6 => SlhDsaParameterSet::Shake128s,
        7 => SlhDsaParameterSet::Shake128f,
        8 => SlhDsaParameterSet::Shake192s,
        9 => SlhDsaParameterSet::Shake192f,
        10 => SlhDsaParameterSet::Shake256s,
        _ => SlhDsaParameterSet::Shake256f,
    }
}

fn expand_bytes(source: &[u8], length: usize) -> Vec<u8> {
    if length == 0 {
        return Vec::new();
    }

    if source.is_empty() {
        return vec![0_u8; length];
    }

    (0..length)
        .map(|index| source[index % source.len()])
        .collect()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let set = parameter_set(data[0]);
    let parameters = set.parameters();
    let slh_dsa = SlhDsa::new(set);

    let mode = data[1] & 1;
    let payload = &data[2..];

    if mode == 0 {
        // Malformed-length / decoder robustness path.
        let public_key_end = payload.len().min(parameters.public_key_bytes);
        let signature_end = payload
            .len()
            .min(public_key_end.saturating_add(parameters.signature_bytes));

        let public_key_bytes = &payload[..public_key_end];
        let signature_bytes = &payload[public_key_end..signature_end];
        let message = &payload[signature_end..];

        let public_key = SlhDsaPublicKey::from_bytes(set, public_key_bytes);
        let signature = SlhDsaSignature::from_bytes(set, signature_bytes);

        if let (Ok(public_key), Ok(signature)) = (public_key, signature) {
            let _ = slh_dsa.verify(&public_key, message, &[], &signature);
        }

        return;
    }

    // Deep-verification path: deterministically expand arbitrary fuzz input
    // into exact-length encodings so the verifier itself is exercised.
    let public_key_bytes = expand_bytes(payload, parameters.public_key_bytes);
    let signature_source = payload
        .get(parameters.public_key_bytes..)
        .unwrap_or(payload);
    let signature_bytes = expand_bytes(signature_source, parameters.signature_bytes);

    let public_key = SlhDsaPublicKey::from_bytes(set, &public_key_bytes)
        .expect("exact-length public key must decode");
    let signature = SlhDsaSignature::from_bytes(set, &signature_bytes)
        .expect("exact-length signature must decode");

    let message = payload;

    let _ = slh_dsa.verify(&public_key, message, &[], &signature);
});

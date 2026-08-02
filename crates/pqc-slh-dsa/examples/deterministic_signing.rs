use pqc_slh_dsa::{SlhDsa, SlhDsaKeyGenSeed, SlhDsaParameterSet, SlhDsaSignature};

fn main() -> Result<(), pqc_slh_dsa::SlhDsaError> {
    let parameter_set = SlhDsaParameterSet::Sha2_128f;
    let implementation = SlhDsa::new(parameter_set);

    let seed_bytes: Vec<u8> = (0..implementation.keygen_seed_bytes())
        .map(|index| 0x40_u8.wrapping_add(index as u8))
        .collect();

    let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes)?;
    let key_pair = implementation.keygen_from_seed(&seed)?;

    let message = b"deterministic SLH-DSA example";
    let context = b"pqc-rs";

    let signature = implementation.sign_deterministic(key_pair.private_key(), message, context)?;

    let encoded = signature.as_bytes().to_vec();
    let decoded = SlhDsaSignature::from_bytes(parameter_set, &encoded)?;

    assert!(implementation.verify(key_pair.public_key(), message, context, &decoded,)?);

    println!("verified deterministic {}-byte signature", encoded.len());

    Ok(())
}

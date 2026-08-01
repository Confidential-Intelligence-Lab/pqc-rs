use pqc_slh_dsa::{SlhDsa, SlhDsaKeyGenSeed, SlhDsaParameterSet};

fn main() -> Result<(), pqc_slh_dsa::SlhDsaError> {
    let parameter_set = SlhDsaParameterSet::Shake128f;
    let implementation = SlhDsa::new(parameter_set);

    let seed_bytes: Vec<u8> = (0..implementation.keygen_seed_bytes())
        .map(|index| index as u8)
        .collect();

    let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes)?;

    let first = implementation.keygen_from_seed(&seed)?;
    let second = implementation.keygen_from_seed(&seed)?;

    assert_eq!(
        first.public_key().as_bytes(),
        second.public_key().as_bytes()
    );
    assert_eq!(
        first.private_key().as_bytes(),
        second.private_key().as_bytes()
    );

    println!(
        "generated deterministic {}-byte public key",
        first.public_key().as_bytes().len()
    );

    Ok(())
}

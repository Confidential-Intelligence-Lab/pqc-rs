use pqc_slh_dsa::{SlhDsa, SlhDsaParameterSet, SlhDsaPreHash};
use rand_core::OsRng;

fn main() -> Result<(), pqc_slh_dsa::SlhDsaError> {
    let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Shake128f);

    let key_pair = slh_dsa.keygen(&mut OsRng)?;

    let message = b"post-quantum signatures";
    let context = b"pqc-rs HashSLH example";

    let signature = slh_dsa.hash_sign_hedged(
        key_pair.private_key(),
        message,
        context,
        SlhDsaPreHash::Sha2_256,
        &mut OsRng,
    )?;

    let verified = slh_dsa.hash_verify(
        key_pair.public_key(),
        message,
        context,
        SlhDsaPreHash::Sha2_256,
        &signature,
    )?;

    assert!(verified);

    Ok(())
}

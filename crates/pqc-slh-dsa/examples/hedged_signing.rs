use pqc_slh_dsa::{SlhDsa, SlhDsaParameterSet};
use rand_core::OsRng;

fn main() -> Result<(), pqc_slh_dsa::SlhDsaError> {
    let implementation = SlhDsa::new(SlhDsaParameterSet::Shake128f);

    let key_pair = implementation.keygen(&mut OsRng)?;

    let message = b"hedged SLH-DSA example";
    let context = b"pqc-rs";

    let signature =
        implementation.sign_hedged(key_pair.private_key(), message, context, &mut OsRng)?;

    assert!(implementation.verify(key_pair.public_key(), message, context, &signature,)?);

    println!(
        "verified hedged {}-byte signature",
        signature.as_bytes().len()
    );

    Ok(())
}

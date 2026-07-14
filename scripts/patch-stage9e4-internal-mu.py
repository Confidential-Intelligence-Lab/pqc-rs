#!/usr/bin/env python3
from pathlib import Path

signing = Path("crates/pqc-ml-dsa/src/signing.rs")
signature = Path("crates/pqc-ml-dsa/src/signature.rs")
verification = Path("crates/pqc-ml-dsa/src/verification.rs")

for path in (signing, signature, verification):
    if not path.exists():
        raise SystemExit(f"Missing {path}; run after Stage 9E-3")

text = signing.read_text(encoding="utf-8")
marker = '''/// Derive the mask-generation seed `rho_double_prime`.
pub fn derive_rho_double_prime(
'''
addition = '''/// Compute the internal-interface message representative.
///
/// This computes `SHAKE256(tr || message_prime, 64)`, where `message_prime`
/// is the input to `ML-DSA.Sign_internal`.
pub fn compute_internal_message_representative(
    tr: &[u8; 64],
    message_prime: &[u8],
) -> [u8; MU_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(tr);
    hasher.update(message_prime);

    let mut reader = hasher.finalize_xof();
    let mut mu = [0_u8; MU_BYTES];
    reader.read(&mut mu);
    mu
}

/// Decode a private key and prepare signing from an externally supplied `mu`.
pub fn prepare_signing_from_mu(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    mu: &[u8; MU_BYTES],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<SigningPreparation, SigningError> {
    let private_key = decode_private_key(parameter_set, encoded_private_key)?;
    let rho_double_prime =
        derive_rho_double_prime(private_key.key(), randomness, mu);

    Ok(SigningPreparation {
        private_key,
        mu: *mu,
        rho_double_prime,
    })
}

/// Decode a private key and prepare the internal signing interface from `M'`.
pub fn prepare_internal_signing(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    message_prime: &[u8],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<SigningPreparation, SigningError> {
    let private_key = decode_private_key(parameter_set, encoded_private_key)?;
    let mu =
        compute_internal_message_representative(private_key.tr(), message_prime);
    let rho_double_prime =
        derive_rho_double_prime(private_key.key(), randomness, &mu);

    Ok(SigningPreparation {
        private_key,
        mu,
        rho_double_prime,
    })
}

'''
if "pub fn prepare_signing_from_mu(" not in text:
    if marker not in text:
        raise SystemExit("Could not locate signing.rs insertion point")
    text = text.replace(marker, addition + marker, 1)
signing.write_text(text, encoding="utf-8")

text = signature.read_text(encoding="utf-8")
text = text.replace(
    '''use crate::signing::{
    prepare_signing, sample_mask_vector, SigningError, SIGNING_RANDOMNESS_BYTES,
};''',
    '''use crate::signing::{
    prepare_internal_signing, prepare_signing, prepare_signing_from_mu,
    sample_mask_vector, SigningError, SigningPreparation,
    SIGNING_RANDOMNESS_BYTES,
};''',
)
old = '''pub fn sign_internal(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    message: &[u8],
    context: &[u8],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<Vec<u8>, SignatureError> {
    let parameters = parameter_set.parameters();
    let beta = parameters.tau as i32 * parameters.eta;
    let gamma2 = gamma2_for(parameter_set);

    let preparation = prepare_signing(
        parameter_set,
        encoded_private_key,
        message,
        context,
        randomness,
    )?;

    let matrix = expand_a(preparation.private_key().rho(), parameter_set)
'''
new = '''pub fn sign_internal(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    message: &[u8],
    context: &[u8],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<Vec<u8>, SignatureError> {
    let preparation = prepare_signing(
        parameter_set,
        encoded_private_key,
        message,
        context,
        randomness,
    )?;
    sign_prepared(parameter_set, preparation)
}

/// Generate a signature through `ML-DSA.Sign_internal` from `M'`.
pub fn sign_internal_message(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    message_prime: &[u8],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<Vec<u8>, SignatureError> {
    let preparation = prepare_internal_signing(
        parameter_set,
        encoded_private_key,
        message_prime,
        randomness,
    )?;
    sign_prepared(parameter_set, preparation)
}

/// Generate a signature through `ML-DSA.Sign_internal` from supplied `mu`.
pub fn sign_internal_mu(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    mu: &[u8; crate::signing::MU_BYTES],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<Vec<u8>, SignatureError> {
    let preparation = prepare_signing_from_mu(
        parameter_set,
        encoded_private_key,
        mu,
        randomness,
    )?;
    sign_prepared(parameter_set, preparation)
}

fn sign_prepared(
    parameter_set: MlDsaParameterSet,
    preparation: SigningPreparation,
) -> Result<Vec<u8>, SignatureError> {
    let parameters = parameter_set.parameters();
    let beta = parameters.tau as i32 * parameters.eta;
    let gamma2 = gamma2_for(parameter_set);

    let matrix = expand_a(preparation.private_key().rho(), parameter_set)
'''
if "pub fn sign_internal_mu(" not in text:
    if old not in text:
        raise SystemExit("Could not locate sign_internal body")
    text = text.replace(old, new, 1)
signature.write_text(text, encoding="utf-8")

text = verification.read_text(encoding="utf-8")
text = text.replace(
    "use crate::signing::compute_message_representative;",
    "use crate::signing::{compute_internal_message_representative, compute_message_representative};",
)
old = '''pub fn verify_internal(
    parameter_set: MlDsaParameterSet,
    encoded_public_key: &[u8],
    message: &[u8],
    context: &[u8],
    encoded_signature: &[u8],
) -> Result<bool, VerificationError> {
    let parameters = parameter_set.parameters();
    let beta = parameters.tau as i32 * parameters.eta;
    let gamma2 = gamma2_for(parameter_set);

    let public_key = decode_public_key(parameter_set, encoded_public_key)?;
    let signature = decode_signature(parameter_set, encoded_signature)?;

    if !vector_infinity_norm_below(
        signature.z(),
        parameters.gamma1 - beta,
    ) {
        return Ok(false);
    }

    let tr = hash_public_key(encoded_public_key);
    let mu = compute_message_representative(&tr, context, message)
        .map_err(|_| VerificationError::ContextTooLong)?;

    let challenge = sample_in_ball_bytes(
'''
new = '''pub fn verify_internal(
    parameter_set: MlDsaParameterSet,
    encoded_public_key: &[u8],
    message: &[u8],
    context: &[u8],
    encoded_signature: &[u8],
) -> Result<bool, VerificationError> {
    let tr = hash_public_key(encoded_public_key);
    let mu = compute_message_representative(&tr, context, message)
        .map_err(|_| VerificationError::ContextTooLong)?;
    verify_with_mu(parameter_set, encoded_public_key, &mu, encoded_signature)
}

/// Verify through `ML-DSA.Verify_internal` from `M'`.
pub fn verify_internal_message(
    parameter_set: MlDsaParameterSet,
    encoded_public_key: &[u8],
    message_prime: &[u8],
    encoded_signature: &[u8],
) -> Result<bool, VerificationError> {
    let tr = hash_public_key(encoded_public_key);
    let mu = compute_internal_message_representative(&tr, message_prime);
    verify_with_mu(parameter_set, encoded_public_key, &mu, encoded_signature)
}

/// Verify through `ML-DSA.Verify_internal` from externally supplied `mu`.
pub fn verify_internal_mu(
    parameter_set: MlDsaParameterSet,
    encoded_public_key: &[u8],
    mu: &[u8; 64],
    encoded_signature: &[u8],
) -> Result<bool, VerificationError> {
    verify_with_mu(parameter_set, encoded_public_key, mu, encoded_signature)
}

fn verify_with_mu(
    parameter_set: MlDsaParameterSet,
    encoded_public_key: &[u8],
    mu: &[u8; 64],
    encoded_signature: &[u8],
) -> Result<bool, VerificationError> {
    let parameters = parameter_set.parameters();
    let beta = parameters.tau as i32 * parameters.eta;
    let gamma2 = gamma2_for(parameter_set);

    let public_key = decode_public_key(parameter_set, encoded_public_key)?;
    let signature = decode_signature(parameter_set, encoded_signature)?;

    if !vector_infinity_norm_below(
        signature.z(),
        parameters.gamma1 - beta,
    ) {
        return Ok(false);
    }

    let challenge = sample_in_ball_bytes(
'''
if "pub fn verify_internal_mu(" not in text:
    if old not in text:
        raise SystemExit("Could not locate verify_internal body")
    text = text.replace(old, new, 1)
verification.write_text(text, encoding="utf-8")

print("Applied Stage 9E-4 internal ML-DSA interfaces.")

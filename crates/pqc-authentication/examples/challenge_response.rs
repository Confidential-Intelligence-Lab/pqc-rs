use pqc_authentication::{
    prove_authentication_hedged, resolve_authentication_profile, AuthenticationVerifier,
};
use pqc_ml_dsa::{MlDsa, MlDsaParameterSet};
use pqc_protocol::{
    negotiate_policy_permitted_common, CapabilityOffer, CapabilityPolicy, PolicyId, ProtocolId,
    ProtocolRole, ProtocolVersion, SessionId, TypedProtocolSession, AUTH_ML_DSA_65,
};
use rand_core::OsRng;

const APPLICATION_CONTEXT: &[u8] = b"pqc-forge/challenge-response-example";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("PQC-Forge ML-DSA-65 challenge-response authentication");
    println!();

    // -----------------------------------------------------------------
    // 1. Negotiate an authentication capability under local policy.
    // -----------------------------------------------------------------

    let capabilities = [AUTH_ML_DSA_65];

    let prover_offer = CapabilityOffer::new(&capabilities)?;
    let verifier_offer = CapabilityOffer::new(&capabilities)?;
    let verifier_policy = CapabilityPolicy::new(PolicyId::new(0x0201), &capabilities)?;

    let negotiated =
        negotiate_policy_permitted_common(prover_offer, verifier_offer, verifier_policy)
            .ok_or_else(|| std::io::Error::other("authentication capability negotiation failed"))?;

    println!(
        "negotiated capability: 0x{:04x}",
        negotiated.capability().value()
    );

    // -----------------------------------------------------------------
    // 2. Establish protocol context carrying validated negotiation
    //    evidence.
    // -----------------------------------------------------------------

    let established = TypedProtocolSession::new(
        SessionId::from_bytes([0x41; 16]),
        ProtocolId::new(0x0200),
        ProtocolVersion::new(1, 0),
        ProtocolRole::Client,
    )
    .begin_establishment()
    .establish_with_negotiation(negotiated);

    let profile = resolve_authentication_profile(&established)?;

    println!("resolved authentication profile: {profile:?}");

    // -----------------------------------------------------------------
    // 3. Provision the prover's ML-DSA-65 key pair.
    //
    //    This example keeps key provisioning deliberately local. Mapping
    //    a public key to a user, device, or service identity is application
    //    policy and is outside this authentication ceremony.
    // -----------------------------------------------------------------

    let implementation = MlDsa::new(MlDsaParameterSet::MlDsa65);
    let mut rng = OsRng;
    let key_pair = implementation.keygen(&mut rng)?;

    // -----------------------------------------------------------------
    // 4. Verifier issues a fresh single-use challenge.
    // -----------------------------------------------------------------

    let verifier =
        AuthenticationVerifier::new(&established, key_pair.public_key(), APPLICATION_CONTEXT);

    let pending = verifier.issue_challenge(&mut rng);

    println!("verifier issued fresh challenge");

    // -----------------------------------------------------------------
    // 5. Prover signs the canonical authentication transcript.
    // -----------------------------------------------------------------

    let proof = prove_authentication_hedged(
        &established,
        pending.challenge(),
        APPLICATION_CONTEXT,
        key_pair.private_key(),
        &mut rng,
    )?;

    println!("prover generated ML-DSA-65 authentication proof");

    // -----------------------------------------------------------------
    // 6. Verifier consumes the pending challenge while verifying the
    //    proof. The PendingAuthentication value cannot be reused.
    // -----------------------------------------------------------------

    let _authenticated = pending.verify(&proof)?;

    println!("authentication succeeded");
    println!();
    println!(
        "The proof is bound to the established protocol context, negotiated \
         capability and policy, verifier challenge, and application context."
    );

    Ok(())
}

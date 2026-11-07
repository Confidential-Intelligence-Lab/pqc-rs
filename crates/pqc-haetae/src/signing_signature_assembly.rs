//! Test-only HAETAE accepted-signature assembly.
//!
//! Mirrors the authenticated HAETAE 1.2.0 C signing hint and PackSIG sequence.

use crate::params::{ParameterSet, N};
use crate::poly::Poly;
use crate::polyvec::{PolyVecK, PolyVecL};
use crate::signature_packing::{pack_signature, SignaturePackingError};
use crate::signing_challenge_prepare::SigningChallengePreparation;
use crate::signing_response::SigningResponse;
use zeroize::Zeroizing;

// HAETAE_10K_7D_4C_8D_ASSEMBLY_LIFECYCLE

fn round_fixed(x: i32) -> i32 {
    x.checked_add(4096)
        .expect("HAETAE fixed-point rounding overflow")
        >> 13
}

fn flatten(polys: &[Poly]) -> Vec<i32> {
    polys
        .iter()
        .flat_map(|poly| poly.coeffs.iter().copied())
        .collect()
}

pub(crate) fn assemble_accepted_signature<const K: usize, const L: usize>(
    mode: ParameterSet,
    prepared: &SigningChallengePreparation<K>,
    response: &SigningResponse<L, K>,
) -> Result<Vec<u8>, SignaturePackingError> {
    assert_eq!(mode.parameters().k, K);
    assert_eq!(mode.parameters().l, L);
    assert_eq!(response.reject1 | response.reject2, 0);

    let z1rnd = Zeroizing::new(PolyVecL::<L>::new(std::array::from_fn(|i| {
        Poly::new(std::array::from_fn(|j| {
            round_fixed(response.z1[i].coeffs[j])
        }))
    })));

    let mut z2rnd = Zeroizing::new(PolyVecK::<K>::new(std::array::from_fn(|i| {
        Poly::new(std::array::from_fn(|j| {
            round_fixed(response.z2[i].coeffs[j])
        }))
    })));

    z2rnd.double();

    let mut htmp = Zeroizing::new(prepared.ay.sub(&z2rnd));
    htmp.freeze2q();

    let htmp_highbits = Zeroizing::new(htmp.highbits_hint(mode));
    let mut h = Zeroizing::new(prepared.highbits.sub(&htmp_highbits));
    h.cadd_dq2alpha(mode);

    let lowbits = Zeroizing::new(z1rnd.lowbits());
    let highbits = Zeroizing::new(z1rnd.highbits());

    let challenge = prepared.challenge.coeffs.as_slice();

    let lowbits_flat: Zeroizing<Vec<i32>> = Zeroizing::new(
        lowbits
            .as_slice()
            .iter()
            .flat_map(|poly| poly.coeffs.iter().copied())
            .collect(),
    );

    let highbits_flat: Zeroizing<Vec<i32>> = Zeroizing::new(
        highbits
            .as_slice()
            .iter()
            .flat_map(|poly| poly.coeffs.iter().copied())
            .collect(),
    );

    let h_flat = Zeroizing::new(flatten(h.as_slice()));

    debug_assert_eq!(lowbits_flat.len(), L * N);
    debug_assert_eq!(highbits_flat.len(), L * N);
    debug_assert_eq!(h_flat.len(), K * N);

    pack_signature(mode, challenge, &lowbits_flat, &highbits_flat, &h_flat)
}

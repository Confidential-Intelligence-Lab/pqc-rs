# S5.D-1: Security-assurance and robustness audit

**Status:** Research diagnostic; conditional quantum security NOT established.
**Upstream verified baseline:** `ff2ba3c9d74220e01023b3ec35d9ae942953aa0d`.
**Depends on:** installed and committed S5.C research profile.

## Source-grounded findings

- The S5.C candidate chooses `n_key=16384`, `k_test_min=16384`, `max_transmissions=100000`, and a 2% Z-test tolerance. The reference Eq. (2) calculation gives 5961 candidate bits, with proof hypotheses **not** verified.
- `s2a2_syndrome_reconciliation.py` has `BLOCK_SIZE=128`, `SYNDROME_ROWS=32`, and an exact decoder guarantee for **at most two errors per block**. A higher-weight error can fail decoding or collide with a low-weight syndrome and then require independent confirmation. A nominal 4096-bit public syndrome budget is consistent with 128 blocks.
- `s2a1_universal_confirmation.py` samples a fresh Toeplitz seed after the input strings are fixed; under its stated uniformity and independence premises, the collision probability is at most `2^-64` for a 64-bit tag. This is **not** a cryptographic authentication advantage.
- `m1e2_privacy_amplification.py` implements a Toeplitz hash using `n+ell-1` seed bits. Its universal-2 proof and quantum leftover hashing applicability need to be cited and linked to independent source assumptions and public transcript accounting.
- `s3d_authentication_contract.py` limits a root credential to one **local** use and budgets outer frames, but explicitly does not count all inner MACs or prove a multi-message HMAC reduction. This limits claims of a complete computational epsilon-authentication budget.

## Illustrative robustness sanity check: not a measured QKD error rate

Suppose X-basis errors are independent Bernoulli random variables with rate 2%, which is an **additional illustrative assumption** and not implied by the protocol's Z-basis QBER tolerance. A 128-bit block lies within the guaranteed correction radius with probability

    P[X <= 2] = sum_{j=0}^2 C(128,j) (0.02)^j (0.98)^(128-j) ~= 0.527085.

Across 128 blocks, the probability **all blocks lie in the guaranteed correction radius** is approximately `2.52e-36`. This is not necessarily the exact probability the algorithm accepts: higher-weight error patterns may alias valid syndromes and confirmation may then reject them. It is a sharp warning that a 2%-error end-to-end throughput claim requires new reconciliation robustness evidence. Zero or near-zero simulated errors may still pass.

## Proof applicability and the cap

The TLGR article describes quota-based BB84 with a full matched-Z sample and a published finite-key equation. To use it, verify the supplementary proof's source assumptions, adversarial causal interactions, stopping process, public transcript, and parameter estimation. The hard cap introduces a public abort filter; source-level record prefix checks do not prove a full quantum accepted-branch coupling. Supplementary Notes S1-S2 were linked on PMC, but the PDF endpoint returned a browser verification barrier when inspected for this increment. Their complete hypotheses remain UNREVIEWED.

## Standards relationship

ETSI GS QKD 005 V1.1.1 distinguishes a scientific security proof of the modeled devices/protocol from implementation verification. This audit serves the **implementation evidence** side; it cannot be substituted for the scientific proof. See https://www.etsi.org/deliver/etsi_gs/QKD/001_099/005/01.01.01_60/gs_QKD005v010101p.pdf.

## Next decisions

1. Validate actual S5.C full-session execution or measured abort behavior under declared X error conditions, not just Eq. (2) feasibility.
2. Decide whether to improve the bounded-distance reconciliation scheme or state a narrower very-low-noise operational research profile. Do not reduce disclosure estimates without proof.
3. Obtain the TLGR supplement and document exact theorem hypotheses; resolve cap and test-size correspondence.
4. Inventory all outer and inner HMAC frame counts, public disclosures, domain separations and key reuse; derive or cite a compatible HMAC computational advantage bound.
5. Independently review the resulting conditional research disposition before changing any security flag.

**Invariants:** `security_qualified=false`, `hpke_export_authorized=false`, `qkd_psk_available=false`.

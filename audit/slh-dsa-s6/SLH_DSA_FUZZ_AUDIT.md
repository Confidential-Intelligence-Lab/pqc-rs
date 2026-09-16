# SLH-DSA S6 structured fuzzing audit

## Scope

This audit records structured robustness testing for the SLH-DSA verification
boundary.

The fuzz target is:

```text
fuzz/fuzz_targets/slhdsa_verification.rs
It exercises all twelve FIPS 205 SLH-DSA parameter sets across the SHA-2 and
SHAKE families.

Properties

The target checks that:

arbitrary public-key and signature inputs do not panic;
malformed encodings fail through structured rejection;
all twelve FIPS 205 parameter sets are selectable;
a dedicated deep-verification path constructs exact-length public-key and
signature encodings so execution reaches the verifier rather than stopping
only at length validation.

The target covers Pure SLH-DSA verification. HashSLH-DSA remains a distinct
future fuzzing target because its prehash selection and message encoding form a
separate external interface.

Smoke campaign

The initial campaign was run with:

cargo +nightly fuzz run slhdsa_verification \
  --fuzz-dir fuzz \
  -- \
  -max_total_time=60

Observed result:

runs:        20,886
duration:    61 s
coverage:    604
features:    1,950
corpus:      119 entries at campaign completion
crashes:     0
panics:      0

The local coverage-derived corpus subsequently contained 127 files totaling
approximately 508 KiB. SHA-named coverage-derived corpus entries are ignored by
repository policy and are not treated as source artifacts.

The repository retains a small deterministic bootstrap corpus covering both
the malformed-decoder and exact-length deep-verification modes. A subsequent
local corpus-seeded run loaded the coverage-derived corpus and initialized at
higher coverage than the empty-corpus campaign.

The campaign reached SLH-DSA signature decoding, exact-length expansion,
SHA-2/SHAKE verification code, and MGF1-related hashing paths.

Evidence boundary

This result is structured robustness evidence. It is not a proof of memory
safety, constant-time behavior, side-channel resistance, or cryptographic
security.

Longer campaigns, additional architectures, and HashSLH-DSA verification
remain useful follow-on assurance work.

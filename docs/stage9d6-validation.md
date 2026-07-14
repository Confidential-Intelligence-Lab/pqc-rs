# Stage 9D-6: ML-DSA Validation and Interoperability Gate

Stage 9D-6 closes the functional KeyGen/Sign/Verify phase.

It adds:

- deterministic and hedged end-to-end matrices;
- empty, short, block-boundary, and long messages;
- contexts from 0 through the 255-byte maximum;
- mutation campaigns across the challenge, response, and hint regions;
- wrong-key and wrong-parameter-set rejection;
- strict decoder checks;
- deterministic 128-bit fingerprints for external comparison;
- a single Stage 9D release gate.

## Run

```bash
python3 scripts/patch-stage9d6-validation.py
./scripts/run-stage9d6.sh
```

## External evidence boundary

Passing this stage establishes internal consistency and robust negative
behavior. It does not by itself establish FIPS 204 conformance.

Before making a conformance claim, compare PQC-rs outputs with:

1. NIST ACVP ML-DSA vector generation/validation;
2. an independent FIPS 204 implementation;
3. the official CRYSTALS-Dilithium reference implementation where the final
   FIPS 204 interface is equivalent.

NIST's ACVP infrastructure is the authoritative source for algorithm
validation. Current ACVP work has included ML-DSA sigGen corner-case fixes, so
the exact ACVP-Server release used must be recorded with the evidence.

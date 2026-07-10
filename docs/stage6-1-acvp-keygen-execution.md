# Stage 6.1: NIST ACVP ML-KEM KeyGen Execution

## Scope

Stage 6.1 is the first stage that executes the implementation against NIST's
published ACVP expected results.

## Added

- deterministic `ML-KEM.KeyGen_internal(d, z)` entry points
- full decapsulation-key assembly: `dkPKE || ek || H(ek) || z`
- ACVP KeyGen command-line runner
- exact `ek` and `dk` byte comparison
- first-mismatch byte offset and context
- total/pass/fail statistics
- nonzero exit status on any mismatch

## Run

First fetch the vectors:

```bash
./scripts/fetch-nist-acvp-ml-kem.sh
```

Then execute KeyGen validation:

```bash
cargo run -p pqc-test-harness \
  --bin ml-kem-acvp-keygen --release
```

An alternate vector root can be provided as the first argument.

## Expected initial outcome

The runner is expected to expose mismatches in the current structural K-PKE
implementation. A mismatch is evidence that the implementation is not yet
conformant; it is not a harness failure.

Ordinary `cargo test` remains offline and does not silently claim that official
vectors were executed.

## Exit criterion

Stage 6.1 is complete only when all NIST ACVP ML-KEM KeyGen cases pass for:

- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

# Stage 8B: Structured Fuzzing

Stage 8B adds five coverage-guided `cargo-fuzz` targets.

## Targets

### `ml_kem_key_checks`

Exercises arbitrary byte strings against:

- encapsulation-key validation;
- decapsulation-key validation;
- all three ML-KEM parameter sets.

Acceptance property: no panic, out-of-bounds access, or uncontrolled resource
growth.

### `ml_kem_decapsulation`

Exercises:

- malformed key and ciphertext lengths;
- exact-length arbitrary decapsulation keys;
- exact-length arbitrary ciphertexts;
- all three parameter sets.

Acceptance property: decapsulation either returns a result or a structured
error without panicking.

### `hpke_vector_parser`

Exercises arbitrary input against the pinned HPKE-PQ JSON model.

Acceptance property: malformed JSON is rejected without panic or excessive
allocation.

### `hpke_receiver_open`

Exercises arbitrary AAD and ciphertext against a valid receiver context.

Acceptance properties:

- authentication failures do not panic;
- failed `Open` does not advance the sequence number.

### `hybrid_kem_inputs`

Exercises:

- arbitrary deterministic randomness lengths;
- arbitrary hybrid ciphertext lengths and contents;
- MLKEM768-P256;
- MLKEM768-X25519;
- MLKEM1024-P384.

Acceptance property: malformed inputs fail cleanly without panics.

## Smoke execution

```bash
./scripts/install-fuzzing-tools.sh
FUZZ_SECONDS=20 ./scripts/run-fuzz-smoke.sh
```

## Longer campaigns

Example:

```bash
cargo +nightly fuzz run   --fuzz-dir fuzz   ml_kem_decapsulation   --   -max_total_time=3600   -timeout=10
```

Crashes are written under `fuzz/artifacts/<target>/`. Every reproducible crash
must become a deterministic regression test before the issue is closed.

## Scope boundary

Fuzzing increases confidence in parser and state-machine robustness. It is not
a proof of memory safety, constant-time behavior, cryptographic security, or
standards conformance.

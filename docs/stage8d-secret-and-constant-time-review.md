# Stage 8D: Secret Lifetime and Constant-Time Review

Stage 8D reviews how secret values are represented, exposed, copied, logged,
compared, and destroyed. It adds automated inventory checks but does not claim
that static pattern matching proves constant-time behavior.

## Review areas

### Secret-bearing types

Review all values containing:

- private keys and decapsulation keys;
- ML-KEM secret seeds;
- ephemeral randomness;
- shared secrets;
- HPKE key-schedule secrets;
- AEAD keys and nonces;
- hybrid KEM traditional private scalars.

Prefer dedicated wrapper types from `pqc_core::secret` for newly exposed public
APIs. Existing validated internals should be migrated incrementally to avoid
combining broad representation changes with algorithmic changes.

### Zeroization boundaries

Zeroization is required for owned secret buffers when their lifetime ends.
Review:

- stack arrays;
- heap vectors;
- temporary KDF inputs;
- expanded private keys;
- copied shared secrets;
- test and trace output.

Zeroization does not guarantee removal of every compiler-generated copy,
register value, swap copy, or crash dump.

### Debug and serialization exposure

Secret-bearing public types must not derive:

- `Debug`;
- `Display`;
- `Serialize`;
- `Clone`, unless duplication is explicitly required and documented.

Where diagnostic formatting is necessary, use a redacted implementation such
as `SecretBytes(REDACTED)`.

### Unsafe code

The preferred policy is no unsafe code in cryptographic crates. Any exception
requires:

1. a documented safety invariant;
2. isolated implementation;
3. dedicated tests;
4. Miri and sanitizer coverage;
5. reviewer approval.

### Constant-time candidates

Manually inspect:

- equality checks over secret-derived values;
- implicit-rejection selection;
- decapsulation validity handling;
- secret-dependent branches;
- secret-dependent table indices;
- variable-time integer operations;
- early returns based on secret state.

Use constant-time primitives from `subtle` where selection or equality depends
on secret data.

## Automated checks

```bash
python3 scripts/patch-stage8d-secret-hygiene.py
./scripts/run-stage8d.sh
```

The scripts produce review inventories under `target/`.

## Acceptance criteria

Stage 8D is complete when:

1. all secret-bearing public types are classified;
2. accidental secret `Debug` exposure is removed;
3. unsafe code is absent or fully reviewed;
4. zeroization boundaries are documented;
5. every branch candidate is classified as public-data-dependent,
   secret-data-dependent, or false positive;
6. secret-dependent equality and selection use constant-time primitives;
7. all existing conformance, negative, Miri, sanitizer, and fuzz gates remain
   clean.

## Claim boundary

A clean Stage 8D review does not prove constant-time execution on every
compiler, target, microarchitecture, or operating system. It establishes a
documented implementation discipline and review baseline.

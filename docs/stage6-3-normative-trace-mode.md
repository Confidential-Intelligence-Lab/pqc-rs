# Stage 6.3: Normative KeyGen Trace Mode

Stage 6.3 adds an opt-in trace path for the first failing NIST ACVP ML-KEM
KeyGen case.

The trace captures:

- `d`
- `z`
- `rho`
- `sigma`
- digest of `A[0][0]`
- digest of `s[0]`
- digest of `e[0]`
- digest of `s_hat[0]`
- digest of `e_hat[0]`
- digest of `t[0]`
- digest of `t_hat[0]`
- actual encapsulation key
- expected encapsulation key
- CPA secret-key component
- first differing encapsulation-key byte

The runner writes binary checkpoints and a JSON summary under:

```text
target/acvp-traces/ml-kem-keygen/<parameter-set>/tg<id>-tc<id>/
```

Run it with:

```bash
cargo run -p pqc-test-harness \
  --bin ml-kem-acvp-keygen-trace \
  --release
```

An optional vector root and output root may be supplied as positional arguments.

The trace is diagnostic evidence only. It does not mark any vector as passed or
change the repository's conformance status.

# Stage 8B

Extract into the repository root.

Install the fuzzing toolchain:

```bash
./scripts/install-fuzzing-tools.sh
```

List targets:

```bash
./scripts/list-fuzz-targets.sh
```

Run bounded smoke campaigns:

```bash
FUZZ_SECONDS=20 ./scripts/run-fuzz-smoke.sh
```

The five targets cover ML-KEM key checks, ML-KEM decapsulation, HPKE vector
parsing, receiver `Open`, and PQ/traditional hybrid KEM inputs.

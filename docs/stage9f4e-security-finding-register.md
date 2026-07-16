# Stage 9F-4E: Security Finding Register

Stage 9F-4D records individual machine-code instructions. Stage 9F-4E
consolidates equivalent instruction records into a compact reviewer-facing
finding register.

## Finding groups

The register groups instructions into findings such as:

- challenge-sampling Result checks;
- eta-sampling Result checks;
- branchless rounding corrections;
- fixed rounding-loop control;
- encoding and decoding Result checks;
- encoding allocator cleanup;
- key generation and signing Result checks;
- public verification-result handling;
- sign/verify allocator and unwind cleanup;
- fixed-offset stack and frame accesses.

## Run

```bash
./scripts/run-stage9f4e-finding-register.sh
```

## Outputs

```text
audit/stage9f4e/security-finding-register.csv
audit/stage9f4e/security-finding-register.md
target/stage9f4e/stage9f4e-audit-summary.md
target/stage9f4e/security-finding-register.md
```

The generator exits nonzero if any instruction cannot be assigned to an
accepted finding.

## Security conclusion boundary

The generated conclusion applies only to the recorded:

- repository commit;
- rustc and LLVM version;
- target architecture;
- compiler flags;
- audited wrapper binary.

It is empirical machine-code evidence, not a formal proof of constant-time
execution.

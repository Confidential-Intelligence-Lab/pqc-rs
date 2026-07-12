# Stage 7D: PQ/Traditional Hybrid HPKE

This stage implements and validates:

| KEM | ID | Nenc | Npk | Nsk | Base suite |
|---|---:|---:|---:|---:|---|
| MLKEM768-P256 | `0x0050` | 1153 | 1249 | 32 | HKDF-SHA256 / AES-128-GCM |
| MLKEM768-X25519 | `0x647a` | 1120 | 1216 | 32 | HKDF-SHA256 / ChaCha20Poly1305 |
| MLKEM1024-P384 | `0x0051` | 1665 | 1665 | 32 | HKDF-SHA384 / AES-256-GCM |

The hybrid combiner computes:

```text
SHA3-256(ss_PQ || ss_T || ct_T || ek_T || Label)
```

The vector harness reuses the pinned Stage 7C corpus and verifies recipient
keys, deterministic hybrid encapsulation, KEM shared secret, Base-mode
ciphertexts, plaintext recovery, and exporter outputs for all three suites.

The implementation target is `draft-ietf-hpke-pq-05` together with the hybrid
KEM constructions it references. These documents remain works in progress.

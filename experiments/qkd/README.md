# CUDA-Q BB84 experimental integration (M1.C)

This is **only a simulated protocol-integration fixture**. It is not a full BB84 security implementation and provides no QKD security guarantee. The output contains shared key bytes in plaintext and must not be used with real data or production key management.

The simulator uses circuit-level single-qubit state preparation/measurement, random basis sifting, and optional intercept-and-resend diagnostics. It lacks authenticated public discussion, information reconciliation, rigorous privacy amplification, finite-key bounds, optical losses, detector models, and adversarial device models. The SHA-256 fixture derivation **does not establish secret key security**.

From the repository root in a Python environment where `import cudaq` works:

```sh
python experiments/qkd/bb84_cudaq.py --bits 1024 --seed 20261120
python experiments/qkd/bb84_cudaq.py --bits 1024 --seed 20261120 --intercept-percent 100
```

The first should yield 0 QBER; the second approximately 25% QBER (statistical variation expected).

To run the end-to-end fixture demo, use a private temporary directory, create an exclusive file (mode 0600), run the Rust HPKE example, and remove the file immediately. The M1.C installation script does this automatically. Do **not** commit key files, print `secret_hex`, or use an exported fixture to protect actual secrets.

# Stage 7B-4: Base Setup, Context State, and AEAD

This combined Stage 7B-3/7B-4 increment implements Base-mode setup, sender and receiver contexts, AES-GCM and ChaCha20Poly1305, sequence-based nonce derivation, message sealing/opening, exporter secrets, and context-state zeroization.

It does not yet claim RFC 9180 vector conformance. Full vector execution remains Stage 7B-5.

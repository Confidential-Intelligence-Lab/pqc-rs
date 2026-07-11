# Stage 6.5B-1 Eta1 Vector Fix

This patch adds the missing parameter-aware `sample_eta1_vector` helper.

Behavior:

- ML-KEM-512 uses `eta1 = 3`
- ML-KEM-768 uses `eta1 = 2`
- ML-KEM-1024 uses `eta1 = 2`

The regression test is also corrected to pass a `&[u8; 32]` seed directly,
matching the helper signature.

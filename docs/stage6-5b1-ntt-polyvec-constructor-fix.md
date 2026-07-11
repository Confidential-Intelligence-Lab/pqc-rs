# Stage 6.5B-1 NTT PolyVec Constructor Fix

`kpke_encrypt.rs` now correctly treats the decoded public-key vector as already
being in NTT representation, but `NttPolyVec` did not yet provide the required
constructor.

This patch adds:

```rust
NttPolyVec::from_sampled_ntt_polyvec(...)
```

The constructor copies coefficients directly into `FipsNttPoly` values and does
not apply a forward NTT.

# Stage 3 Fix: Compression Test Boundary

The original Stage 3 test used ordinary absolute distance:

```rust
abs(reduce(x) - decompress(compress(x)))
```

That is incorrect at the boundary of `Z_q`. For example, a value near `q - 1`
may decompress to `0`, which is close modulo `q` but far under ordinary integer
distance.

The corrected test uses circular distance modulo `q`:

```rust
min(abs(a - b), q - abs(a - b))
```

This reflects the coefficient ring semantics used by ML-KEM.

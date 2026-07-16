# Stage 10B-2: Constant-Time Byte Comparison

Adds `ct_eq_bytes`, `ct_is_zero_bytes`, `ct_eq_slices`, and `ct_is_zero_slice`. Equal-length comparisons process every byte. Slice length is public. Includes mismatch-position tests, large arrays, an audit binary, and a 30,000-sample timing screen.

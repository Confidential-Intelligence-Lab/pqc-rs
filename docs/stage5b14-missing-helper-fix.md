# Stage 5B-14 Missing Helper Fix

Stage 5B-14 updated K-PKE key generation and encryption to call
`matrix_vector_mul_add_to_polyvec`, but the helper was omitted from the generated
NTT-domain module.

This patch adds the missing helper. It computes the NTT-domain matrix-vector
product, converts it to coefficient-domain polynomials, and adds the
coefficient-domain error vector.

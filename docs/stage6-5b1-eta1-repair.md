# Stage 6.5B-1 Eta1 Repair

The earlier patch searched for an exact documentation marker before
`sample_eta2_vector`. This repair instead locates the function declaration
itself and inserts `sample_eta1_vector` immediately before it.

It also:

- adds `sample_eta3_poly` to the imports;
- uses eta3 for ML-KEM-512;
- uses eta2 for ML-KEM-768 and ML-KEM-1024;
- repairs the regression test to pass `&[u8; 32]`.

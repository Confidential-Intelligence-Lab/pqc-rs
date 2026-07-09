# ML-KEM KAT Manifest

Stage 2 defines the KAT harness shape but does not yet check normative FIPS 203
vectors. Stage 3 will replace the scaffold vectors with official ML-KEM KATs.

Expected vector fields:

```text
parameter_set = ML-KEM-512 | ML-KEM-768 | ML-KEM-1024
seed = hex
public_key = hex
secret_key = hex
ciphertext = hex
shared_secret = hex
```

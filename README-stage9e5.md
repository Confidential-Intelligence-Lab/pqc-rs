# Stage 9E-5

```bash
unzip -o pqc-rs-stage9e5-hash-mldsa-acvp.zip
cp -R pqc-rs/. .
rm -rf pqc-rs

python3 scripts/patch-stage9e5-hash-mldsa.py
./scripts/run-stage9e5-hash-mldsa.sh
```

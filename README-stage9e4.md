# Stage 9E-4

```bash
unzip -o pqc-rs-stage9e4-mldsa-internal-mu-acvp.zip
cp -R pqc-rs/. .
rm -rf pqc-rs
python3 scripts/patch-stage9e4-internal-mu.py
./scripts/run-stage9e4-internal-mu.sh
```

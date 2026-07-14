# Stage 9E-3

```bash
unzip -o pqc-rs-stage9e3-mldsa-acvp-sigver-pure.zip
cp -R pqc-rs/. .
rm -rf pqc-rs

python3 scripts/patch-stage9e3-mldsa-sigver.py
./scripts/run-stage9e3-mldsa-sigver.sh
```

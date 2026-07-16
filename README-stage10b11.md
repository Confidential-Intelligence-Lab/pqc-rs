# Stage 10B-1.1

```bash
unzip -o pqc-rs-stage10b11-production-ct-primitives.zip
cp -R pqc-rs/. .
rm -rf pqc-rs

python3 scripts/patch-stage10b11-enable-ct.py
./scripts/run-stage10b11-ct-primitives.sh
```

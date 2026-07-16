# Stage 10B-1

```bash
unzip -o pqc-rs-stage10b1-ct-primitives.zip
cp -R pqc-rs/. .
rm -rf pqc-rs

python3 scripts/patch-stage10b1-enable-ct.py
./scripts/run-stage10b1-ct-primitives.sh
```

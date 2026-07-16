# Stage 9F-3

```bash
unzip -o pqc-rs-stage9f3-signing-rejection-trace.zip
cp -R pqc-rs/. .
rm -rf pqc-rs

python3 scripts/patch-stage9f3-signing-trace.py
./scripts/run-stage9f3-rejection-trace.sh
```

Evidence is written under `target/stage9f3/`.

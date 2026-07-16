# Stage 9F-2B

```bash
unzip -o pqc-rs-stage9f2b-work-equivalence.zip
cp -R pqc-rs/. .
rm -rf pqc-rs

python3 scripts/patch-stage9f2b-audit-module.py
./scripts/run-stage9f2b-work-equivalence.sh
```

Evidence is written under `target/stage9f2b/`.

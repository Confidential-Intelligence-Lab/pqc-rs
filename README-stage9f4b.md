# Stage 9F-4B

```bash
unzip -o pqc-rs-stage9f4b-secret-dependency-audit.zip
cp -R pqc-rs/. .
rm -rf pqc-rs

./scripts/run-stage9f4b-secret-dependency-audit.sh
```

Review `target/stage9f4b/triage-summary.md` first, then inspect the matching
release assembly excerpts.

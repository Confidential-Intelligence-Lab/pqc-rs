# Stage 9F-4

```bash
unzip -o pqc-rs-stage9f4-generated-code-audit.zip
cp -R pqc-rs/. .
rm -rf pqc-rs

./scripts/run-stage9f4-generated-code-audit.sh
```

Optional Linux workflow:

```bash
./scripts/run-stage9f4-linux-valgrind.sh
```

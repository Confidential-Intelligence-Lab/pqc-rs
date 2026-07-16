# Stage 9F-4D

```bash
unzip -o pqc-rs-stage9f4d-data-dependency-audit.zip
cp -R pqc-rs/. .
rm -rf pqc-rs

./scripts/run-stage9f4d-classification.sh
```

Edit:

```text
audit/stage9f4d/instruction-classification.csv
```

Then validate:

```bash
./scripts/validate-stage9f4d-classification.sh
```

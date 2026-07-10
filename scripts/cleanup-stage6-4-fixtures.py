#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-ml-kem/src/intermediate_values.rs")
if not path.exists():
    raise SystemExit(f"{path} not found; run from repository root")

text = path.read_text(encoding="utf-8")

text = text.replace(
    "kpke_keygen::expand_keygen_seed(&keygen_seed)",
    "kpke_keygen::expand_keygen_seed_for_parameter_set(\n"
    "            parameter_set,\n"
    "            &keygen_seed,\n"
    "        )",
)

for old, new in {
    '"stage5b15-ml-kem-512"': '"stage6-4-acvp-keygen-ml-kem-512"',
    '"stage5b15-ml-kem-768"': '"stage6-4-acvp-keygen-ml-kem-768"',
    '"stage5b15-ml-kem-1024"': '"stage6-4-acvp-keygen-ml-kem-1024"',
}.items():
    text = text.replace(old, new)

marker = "    #[test]\n    fn parameter_sets_produce_distinct_fixture_digests() {\n"
test = '''    #[test]
    fn fixture_public_keys_end_with_their_rho_seed() {
        for fixture in [
            build_ml_kem_512_fixture().unwrap(),
            build_ml_kem_768_fixture().unwrap(),
            build_ml_kem_1024_fixture().unwrap(),
        ] {
            let rho_offset = fixture.public_key.len() - 32;
            assert_eq!(&fixture.public_key[rho_offset..], fixture.rho);
        }
    }

'''

if "fixture_public_keys_end_with_their_rho_seed" not in text:
    if marker not in text:
        raise SystemExit("Could not locate fixture test insertion point")
    text = text.replace(marker, test + marker, 1)

path.write_text(text, encoding="utf-8")
print(f"Updated {path}")

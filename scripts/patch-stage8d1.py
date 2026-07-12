#!/usr/bin/env python3
from pathlib import Path

targets = {
"crates/pqc-ml-kem/src/kpke_keygen.rs": [
("#[derive(Clone, Debug, Eq, PartialEq)]\npub struct KpkeSeedMaterial",
 "#[derive(Clone, Eq, PartialEq)]\npub struct KpkeSeedMaterial"),
("#[derive(Clone, Debug, Eq, PartialEq)]\npub struct KpkeKeygenOutput",
 "#[derive(Clone, Eq, PartialEq)]\npub struct KpkeKeygenOutput"),
],
"crates/pqc-ml-kem/src/ml_kem_keygen.rs": [
("#[derive(Clone, Debug, Eq, PartialEq)]\npub struct MlKemKeygenOutput",
 "#[derive(Clone, Eq, PartialEq)]\npub struct MlKemKeygenOutput"),
],
"crates/pqc-ml-kem/src/ml_kem_encaps.rs": [
("#[derive(Clone, Debug)]\npub struct MlKemEncapsulationOutput",
 "#[derive(Clone)]\npub struct MlKemEncapsulationOutput"),
],
"crates/pqc-ml-kem/src/ml_kem_decaps.rs": [
("#[derive(Clone, Debug)]\npub struct MlKemDecapsulationOutput",
 "#[derive(Clone)]\npub struct MlKemDecapsulationOutput"),
],
"crates/pqc-hpke/src/ml_kem.rs": [
("#[derive(Clone, Debug, Eq, PartialEq)]\npub struct MlKemHpkeKeyPair",
 "#[derive(Clone, Eq, PartialEq)]\npub struct MlKemHpkeKeyPair"),
("#[derive(Clone, Debug, Eq, PartialEq)]\npub struct MlKemHpkeEncapsulation",
 "#[derive(Clone, Eq, PartialEq)]\npub struct MlKemHpkeEncapsulation"),
],
"crates/pqc-hpke/src/hybrid_kem.rs": [
("#[derive(Clone, Debug)]\npub struct HybridKeyPair",
 "#[derive(Clone)]\npub struct HybridKeyPair"),
("#[derive(Clone, Debug, Eq, PartialEq)]\npub struct HybridEncapsulation",
 "#[derive(Clone, Eq, PartialEq)]\npub struct HybridEncapsulation"),
],
"crates/pqc-hpke/src/key_schedule.rs": [
("#[derive(Clone, Debug, Eq, PartialEq)]\npub struct KeyScheduleOutput",
 "#[derive(Clone, Eq, PartialEq)]\npub struct KeyScheduleOutput"),
],
}

for name, replacements in targets.items():
    path = Path(name)
    text = path.read_text()
    for old, new in replacements:
        text = text.replace(old, new)
    path.write_text(text)
    print("updated", path)

path = Path("crates/pqc-ml-kem/src/kpke_keygen.rs")
text = path.read_text()
text = text.replace("assert_eq!(expand_keygen_seed(&seed), expand_keygen_seed(&seed));",
                    "assert!(expand_keygen_seed(&seed) == expand_keygen_seed(&seed));")
text = text.replace("assert_ne!(k512, k768);", "assert!(k512 != k768);")
text = text.replace("assert_ne!(k768, k1024);", "assert!(k768 != k1024);")
text = text.replace("assert_ne!(k512, k1024);", "assert!(k512 != k1024);")
text = text.replace("assert_eq!(a, b);", "assert!(a == b);")
path.write_text(text)

path = Path("crates/pqc-ml-kem/src/ml_kem_keygen.rs")
text = path.read_text()
for alg in ["512", "768", "1024"]:
    old = f"""assert_eq!(
            ml_kem_{alg}_keygen_internal(&d, &z).unwrap(),
            ml_kem_{alg}_keygen_internal(&d, &z).unwrap()
        );"""
    new = f"""assert!(
            ml_kem_{alg}_keygen_internal(&d, &z).unwrap()
                == ml_kem_{alg}_keygen_internal(&d, &z).unwrap()
        );"""
    text = text.replace(old, new)
path.write_text(text)

print("Stage 8D-1 applied.")

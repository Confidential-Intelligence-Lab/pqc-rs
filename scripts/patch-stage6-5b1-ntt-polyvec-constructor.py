#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-ml-kem/src/kpke_ntt_domain.rs")
if not path.exists():
    raise SystemExit(f"{path} not found; run from repository root")

text = path.read_text(encoding="utf-8")

method = '''    /// Construct from coefficients that are already in ML-KEM NTT order.
    ///
    /// This must be used for vectors decoded from `ByteDecode12` public-key
    /// components and for values produced directly by `SampleNTT`.
    pub fn from_sampled_ntt_polyvec(polyvec: &PolyVec) -> Self {
        let mut out = Self::zero(polyvec.rank());
        let mut index = 0usize;

        while index < polyvec.rank() {
            out.polys[index] = FipsNttPoly::from_coefficients(
                *polyvec.as_slice()[index].coefficients(),
            );
            index += 1;
        }

        out
    }

'''

if "pub fn from_sampled_ntt_polyvec" not in text:
    marker = "    /// Return the active rank.\n"
    if marker not in text:
        raise SystemExit("Could not locate NttPolyVec insertion point")
    text = text.replace(marker, method + marker, 1)
    path.write_text(text, encoding="utf-8")
    print(f"Updated {path}")
else:
    print("NTT-preserving PolyVec constructor already present.")

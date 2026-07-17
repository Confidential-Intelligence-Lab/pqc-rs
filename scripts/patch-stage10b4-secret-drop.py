#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-core/src/ct/container.rs")
text = path.read_text(encoding="utf-8")

text = text.replace(
    "use super::{ct_assign_bytes, ct_select_bytes, CtMask8};",
    "use super::{ct_assign_bytes, ct_select_bytes, zeroize_bytes, CtMask8};",
)

drop_impl = """
impl<const LENGTH: usize> Drop for SecretBytes<LENGTH> {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.bytes);
    }
}

"""

if "impl<const LENGTH: usize> Drop for SecretBytes<LENGTH>" not in text:
    marker = "impl<const LENGTH: usize> From<[u8; LENGTH]> for SecretBytes<LENGTH> {"
    index = text.find(marker)
    if index < 0:
        raise SystemExit("Could not locate SecretBytes From implementation")
    text = text[:index] + drop_impl + text[index:]

path.write_text(text, encoding="utf-8")
print("Enabled SecretBytes drop zeroization.")

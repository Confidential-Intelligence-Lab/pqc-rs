#!/usr/bin/env python3
from pathlib import Path

root_manifest = Path("Cargo.toml")
hpke_manifest = Path("crates/pqc-hpke/Cargo.toml")
hpke_lib = Path("crates/pqc-hpke/src/lib.rs")
kdf_path = Path("crates/pqc-hpke/src/kdf.rs")
error_path = Path("crates/pqc-hpke/src/error.rs")
for path in [root_manifest, hpke_manifest, hpke_lib, kdf_path, error_path]:
    if not path.exists():
        raise SystemExit(f"{path} not found; run from repository root")

def ensure_dependency(text, section, key, line):
    marker = f"[{section}]"
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"Missing section [{section}]")
    next_section = text.find("\n[", start + len(marker))
    end = len(text) if next_section < 0 else next_section
    for existing in text[start:end].splitlines():
        if "=" in existing and existing.split("=", 1)[0].strip() == key:
            return text
    return text[:end].rstrip() + "\n" + line + "\n\n" + text[end:].lstrip("\n")

text = root_manifest.read_text()
for key, line in [("aes-gcm", 'aes-gcm = "0.10"'), ("chacha20poly1305", 'chacha20poly1305 = "0.10"')]:
    text = ensure_dependency(text, "workspace.dependencies", key, line)
root_manifest.write_text(text)

text = hpke_manifest.read_text()
for key, line in [
    ("aes-gcm", "aes-gcm = { workspace = true }"),
    ("chacha20poly1305", "chacha20poly1305 = { workspace = true }"),
    ("zeroize", "zeroize = { workspace = true }"),
]:
    text = ensure_dependency(text, "dependencies", key, line)
hpke_manifest.write_text(text)

text = hpke_lib.read_text()
for declaration in ["pub mod aead;\n", "pub mod context;\n", "pub mod setup;\n"]:
    if declaration not in text:
        text = text.rstrip() + "\n" + declaration
hpke_lib.write_text(text)

text = kdf_path.read_text()
if "pub const fn from_id" not in text:
    marker = "    /// Return the HPKE KDF identifier.\n"
    method = """    /// Resolve an RFC 9180 KDF identifier.
    pub const fn from_id(id: KdfId) -> Option<Self> {
        match id.0 {
            0x0001 => Some(Self::HkdfSha256),
            0x0002 => Some(Self::HkdfSha384),
            0x0003 => Some(Self::HkdfSha512),
            _ => None,
        }
    }

"""
    if marker not in text:
        raise SystemExit("Could not locate KDF method insertion point")
    text = text.replace(marker, method + marker, 1)
    kdf_path.write_text(text)

text = error_path.read_text()
enum_start = text.find("pub enum HpkeError")
enum_end = text.find("\n}", enum_start)
variants = [
    ("KemIdentifierMismatch", "    /// The KEM identifier does not match the selected KEM.\n    KemIdentifierMismatch,\n"),
    ("UnsupportedKdf", "    /// The selected KDF identifier is unsupported.\n    UnsupportedKdf,\n"),
    ("UnsupportedAead", "    /// The selected AEAD identifier is unsupported.\n    UnsupportedAead,\n"),
    ("KemError", "    /// KEM setup failed.\n    KemError,\n"),
    ("InvalidAeadKey", "    /// The AEAD key length is invalid.\n    InvalidAeadKey,\n"),
    ("InvalidAeadNonce", "    /// The AEAD nonce length is invalid.\n    InvalidAeadNonce,\n"),
    ("SealError", "    /// AEAD encryption failed.\n    SealError,\n"),
    ("OpenError", "    /// AEAD authentication or decryption failed.\n    OpenError,\n"),
    ("ExportOnly", "    /// The context is export-only.\n    ExportOnly,\n"),
    ("MessageLimitReached", "    /// The HPKE message limit has been reached.\n    MessageLimitReached,\n"),
]
for name, block in variants:
    if name not in text[enum_start:enum_end]:
        text = text[:enum_end] + "\n" + block.rstrip() + text[enum_end:]
        enum_end = text.find("\n}", enum_start)
marker = '''                Self::KdfIdentifierMismatch => {
                    "KDF implementation does not match suite identifier"
                }
'''
extra = '''                Self::KemIdentifierMismatch => {
                    "KEM implementation does not match suite identifier"
                }
                Self::UnsupportedKdf => "unsupported HPKE KDF",
                Self::UnsupportedAead => "unsupported HPKE AEAD",
                Self::KemError => "HPKE KEM operation failed",
                Self::InvalidAeadKey => "invalid AEAD key length",
                Self::InvalidAeadNonce => "invalid AEAD nonce length",
                Self::SealError => "AEAD encryption failed",
                Self::OpenError => "AEAD authentication or decryption failed",
                Self::ExportOnly => "message operation on export-only context",
                Self::MessageLimitReached => "HPKE message limit reached",
'''
if "Self::KemIdentifierMismatch =>" not in text:
    if marker not in text:
        raise SystemExit("Could not locate HpkeError display insertion point")
    text = text.replace(marker, marker + extra, 1)
error_path.write_text(text)
print("Stage 7B-4 manifest and module patch applied.")

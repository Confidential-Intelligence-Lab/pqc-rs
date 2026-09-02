#!/usr/bin/env python3
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, pathlib, subprocess, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from hpke.hpke_core import setup_base

PARAMS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
PROVIDERS = {
    "rust": ["python3", "scripts/interop/providers/rust_provider.py"],
    "liboqs": ["python3", "scripts/interop/providers/liboqs_provider.py"],
    "openssl": ["python3", "scripts/interop/providers/openssl_provider.py"],
}
PAIRS = [("rust", "liboqs"), ("liboqs", "rust"), ("rust", "openssl"), ("openssl", "rust")]


def seed(tag: str) -> str:
    return hashlib.sha256(tag.encode()).hexdigest()


def call(root: pathlib.Path, provider: str, operation: str, ps: str, inputs: dict) -> dict:
    req = {"protocol_version": 1, "action": "execute", "operation": operation, "parameter_set": ps, "inputs": inputs}
    cp = subprocess.run(PROVIDERS[provider], cwd=root, input=json.dumps(req), text=True, capture_output=True, env=os.environ.copy())
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or cp.stdout.strip())
    response = json.loads(cp.stdout)
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error")))
    return response["outputs"]


def keygen(root: pathlib.Path, provider: str, ps: str, tag: str) -> dict:
    inputs = {
        "d": seed(tag + "-d"),
        "z": seed(tag + "-z"),
    }
    return call(root, provider, "kem-keygen", ps, inputs)


def encaps(root: pathlib.Path, provider: str, ps: str, pk: str, tag: str) -> dict:
    inputs = {
        "public_key": pk,
        "m": seed(tag + "-m"),
    }
    return call(root, provider, "kem-encaps", ps, inputs)


def decaps(root: pathlib.Path, provider: str, ps: str, kg: dict, ct: str) -> dict:
    inputs = {
        "secret_key": kg["secret_key"],
        "ciphertext": ct,
    }
    return call(root, provider, "kem-decaps", ps, inputs)


def native_binary(root: pathlib.Path) -> pathlib.Path:
    target_root = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
    candidate = target_root / "debug" / "hpke-native-transcript"
    if os.name == "nt":
        candidate = candidate.with_suffix(".exe")
    if not candidate.exists():
        cp = subprocess.run(
            ["cargo", "build", "--quiet", "-p", "pqc-rs-test-harness", "--bin", "hpke-native-transcript"],
            cwd=root,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
        )
        if cp.returncode != 0:
            raise RuntimeError(cp.stderr.strip() or "failed to build native HPKE transcript binary")
    if not candidate.exists():
        raise RuntimeError(f"native HPKE transcript binary not found at {candidate}")
    return candidate


def native_transcript(binary: pathlib.Path, ps: str, shared_secret: bytes, info: bytes, aad: bytes,
                      plaintext: bytes, exporter_context: bytes, exporter_length: int) -> dict:
    request = {
        "parameter_set": ps,
        "shared_secret": shared_secret.hex(),
        "info": info.hex(),
        "aad": aad.hex(),
        "plaintext": plaintext.hex(),
        "exporter_context": exporter_context.hex(),
        "exporter_length": exporter_length,
    }
    cp = subprocess.run([str(binary)], input=json.dumps(request), text=True, capture_output=True)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or cp.stdout.strip())
    response = json.loads(cp.stdout)
    if not response.get("ok"):
        raise RuntimeError("native HPKE transcript execution failed")
    return response


def reference_transcript(ps: str, shared_secret: bytes, info: bytes, aad: bytes,
                         plaintext: bytes, exporter_context: bytes, exporter_length: int) -> dict:
    sender = setup_base(ps, shared_secret, info)
    receiver = setup_base(ps, shared_secret, info)
    ciphertext, sender_after = sender.seal(aad, plaintext)
    opened, receiver_after = receiver.open(aad, ciphertext)
    sender_export = sender_after.export(exporter_context, exporter_length)
    receiver_export = receiver_after.export(exporter_context, exporter_length)
    if sender_export != receiver_export:
        raise RuntimeError("reference sender and receiver exporter outputs differ")
    return {
        "key": sender.key.hex(),
        "base_nonce": sender.base_nonce.hex(),
        "exporter_secret": sender.exporter_secret.hex(),
        "key_schedule_context": sender.key_schedule_context.hex(),
        "ciphertext": ciphertext.hex(),
        "opened": opened.hex(),
        "exported_secret": sender_export.hex(),
        "sender_sequence": sender_after.sequence,
        "receiver_sequence": receiver_after.sequence,
    }


def run_case(root: pathlib.Path, binary: pathlib.Path, ps: str, sender: str, receiver: str) -> dict:
    tag = f"a3.1:{ps}:{sender}:{receiver}"
    kg = keygen(root, receiver, ps, tag)
    enc = encaps(root, sender, ps, kg["public_key"], tag)
    dec = decaps(root, receiver, ps, kg, enc["ciphertext"])
    if enc["shared_secret"] != dec["shared_secret"]:
        raise RuntimeError("KEM shared-secret mismatch")

    shared_secret = bytes.fromhex(enc["shared_secret"])
    info = b"pqc-rfc9958-rs/a3.1"
    aad = b"hpke-native-aad"
    plaintext = b"native Rust post-quantum HPKE interoperability"
    exporter_context = b"a3.1-export"
    exporter_length = 32

    native = native_transcript(binary, ps, shared_secret, info, aad, plaintext, exporter_context, exporter_length)
    reference = reference_transcript(ps, shared_secret, info, aad, plaintext, exporter_context, exporter_length)
    compared = [
        "key", "base_nonce", "exporter_secret", "key_schedule_context", "ciphertext",
        "opened", "exported_secret", "sender_sequence", "receiver_sequence",
    ]
    mismatches = [field for field in compared if native[field] != reference[field]]
    return {
        "decision": "pass" if not mismatches else "fail",
        "mismatches": mismatches,
        "enc_bytes": len(bytes.fromhex(enc["ciphertext"])),
        "hpke_ciphertext_bytes": len(bytes.fromhex(native["ciphertext"])),
        "transcript_fields_compared": len(compared),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--output", default="target/interop-hpke")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()
    root = pathlib.Path(args.root).resolve()
    results = []
    findings = []

    try:
        binary = native_binary(root)
    except Exception as exc:
        print(f"native HPKE setup failed: {exc}", file=sys.stderr)
        return 1

    for ps in PARAMS:
        for sender, receiver in PAIRS:
            ident = f"{ps}:{sender}->{receiver}"
            try:
                result = run_case(root, binary, ps, sender, receiver)
                result.update({"case": ident, "parameter_set": ps, "sender_kem": sender, "receiver_kem": receiver})
                results.append(result)
                if result["decision"] != "pass":
                    findings.append({"severity": "error", "code": "NATIVE_HPKE_TRANSCRIPT_MISMATCH", "message": f"{ident}: {', '.join(result['mismatches'])}"})
            except Exception as exc:
                results.append({"case": ident, "parameter_set": ps, "sender_kem": sender, "receiver_kem": receiver, "decision": "fail", "reason": str(exc)})
                findings.append({"severity": "error", "code": "NATIVE_HPKE_EXECUTION_FAILED", "message": f"{ident}: {exc}"})

    passed = sum(result["decision"] == "pass" for result in results)
    failed = len(results) - passed
    decision = "pass" if failed == 0 else "fail"
    report = {
        "schema_version": 2,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "decision": decision,
        "strict": args.strict,
        "profile": {
            "mode": "base",
            "kdf": "HKDF-SHA256",
            "aead": "AES-128-GCM",
            "framework": "RFC 9180",
            "pq_kem_binding": "draft-ietf-hpke-pq-05",
            "hpke_implementation": "native Rust pqc-rs-hpke",
            "differential_oracle": "independent Python RFC 9180 transcript",
        },
        "summary": {"executed": len(results), "passed": passed, "failed": failed},
        "results": results,
        "findings": findings,
        "claim_boundary": "A pass demonstrates exact RFC 9180 Base-mode transcript agreement between the native Rust HPKE implementation and an independent reference oracle, while ML-KEM shared secrets cross the native Rust, liboqs, and OpenSSL provider boundaries. It does not claim RFC 9180 Auth or AuthPSK support.",
    }
    out = root / args.output
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        "# A3.1 Native Rust Post-Quantum HPKE Report", "", f"- Decision: **{decision}**",
        f"- Executed: {len(results)}", f"- Passed: {passed}", f"- Failed: {failed}", "",
        "Profile: native Rust RFC 9180 Base mode, HKDF-SHA256, AES-128-GCM, with ML-KEM bindings from `draft-ietf-hpke-pq-05`.", "",
        "Each passing case agrees with the independent reference transcript for the derived key, base nonce, exporter secret, key-schedule context, ciphertext, opened plaintext, exported secret, and sender/receiver sequence numbers.", "",
        "| Parameter set | Sender KEM | Receiver KEM | Transcript fields | Decision |",
        "|---|---|---|---:|---|",
    ]
    for result in results:
        lines.append(f"| `{result['parameter_set']}` | `{result['sender_kem']}` | `{result['receiver_kem']}` | {result.get('transcript_fields_compared', 0)} | **{result['decision']}** |")
    lines += ["", "## Findings", ""] + ([f"- **{finding['code']}**: {finding['message']}" for finding in findings] if findings else ["No findings."])
    lines += ["", "## Claim boundary", "", report["claim_boundary"], ""]
    (out / "report.md").write_text("\n".join(lines))
    print(f"decision={decision}\nexecuted={len(results)}\npassed={passed}\nfailed={failed}\nreport={out/'report.md'}")
    return 0 if decision == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

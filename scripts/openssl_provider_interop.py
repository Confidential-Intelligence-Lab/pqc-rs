#!/usr/bin/env python3
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, pathlib, subprocess

PARAMS_KEM = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
PARAMS_DSA = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
PROVIDERS = {
    "rust": ["python3", "scripts/interop/providers/rust_provider.py"],
    "openssl": ["python3", "scripts/interop/providers/openssl_provider.py"],
}

def call(root: pathlib.Path, provider: str, operation: str, parameter_set: str, inputs: dict) -> dict:
    request = {"protocol_version": 1, "action": "execute", "operation": operation,
               "parameter_set": parameter_set, "inputs": inputs}
    completed = subprocess.run(PROVIDERS[provider], cwd=root, input=json.dumps(request), text=True,
                               capture_output=True, env=os.environ.copy())
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    response = json.loads(completed.stdout)
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error")))
    return response["outputs"]

def seed(tag: str) -> str:
    return hashlib.sha256(tag.encode()).hexdigest()

def run_case(root: pathlib.Path, algorithm: str, ps: str, producer: str, consumer: str):
    if algorithm == "ML-KEM" and producer == "rust":
        kg = call(
            root,
            "rust",
            "kem-keygen",
            ps,
            {
                "d": seed(ps + "-openssl-d"),
                "z": seed(ps + "-openssl-z"),
            },
        )
        enc = call(
            root,
            "openssl",
            "kem-encaps",
            ps,
            {
                "public_key": kg["public_key"],
                "m": seed(ps + "-openssl-m"),
            },
        )
        dec = call(
            root,
            "rust",
            "kem-decaps",
            ps,
            {
                "secret_key": kg["secret_key"],
                "ciphertext": enc["ciphertext"],
            },
        )
        return (
            enc["shared_secret"] == dec["shared_secret"],
            len(enc["ciphertext"]) // 2,
        )
    if algorithm == "ML-KEM":
        kg = call(
            root,
            "openssl",
            "kem-keygen",
            ps,
            {
                "d": seed(ps + "-openssl-d"),
                "z": seed(ps + "-openssl-z"),
            },
        )
        enc = call(
            root,
            "rust",
            "kem-encaps",
            ps,
            {
                "public_key": kg["public_key"],
                "m": seed(ps + "-openssl-m"),
            },
        )
        dec = call(
            root,
            "openssl",
            "kem-decaps",
            ps,
            {
                "secret_key": kg["secret_key"],
                "ciphertext": enc["ciphertext"],
            },
        )
        return (
            enc["shared_secret"] == dec["shared_secret"],
            len(enc["ciphertext"]) // 2,
        )
    message, context = seed(ps + "-openssl-message"), "41322e34"
    if producer == "rust":
        kg = call(root, "rust", "dsa-keygen", ps, {"xi": seed(ps + "-openssl-xi")})
        sig = call(root, "rust", "dsa-sign", ps, {"secret_key": kg["secret_key"], "message": message,
                   "context": context, "randomness": "00" * 32})
        ver = call(root, "openssl", "dsa-verify", ps, {"public_key": kg["public_key"], "message": message,
                   "context": context, "signature": sig["signature"]})
    else:
        kg = call(
            root,
            "openssl",
            "dsa-keygen",
            ps,
            {
                "xi": seed(ps + "-openssl-xi"),
            },
        )
        sig = call(
            root,
            "openssl",
            "dsa-sign",
            ps,
            {
                "secret_key": kg["secret_key"],
                "message": message,
                "context": context,
                "randomness": "00" * 32,
            },
        )
        ver = call(
            root,
            "rust",
            "dsa-verify",
            ps,
            {
                "public_key": kg["public_key"],
                "message": message,
                "context": context,
                "signature": sig["signature"],
            },
        )
    return bool(ver["valid"]), len(sig["signature"]) // 2

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="target/interop-openssl")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    root = pathlib.Path(args.root).resolve()
    cases = []
    for ps in PARAMS_KEM:
        cases.extend([("ML-KEM", ps, "rust", "openssl"), ("ML-KEM", ps, "openssl", "rust")])
    for ps in PARAMS_DSA:
        cases.extend([("ML-DSA", ps, "rust", "openssl"), ("ML-DSA", ps, "openssl", "rust")])
    results, findings = [], []
    for algorithm, ps, producer, consumer in cases:
        ident = f"{ps}:{producer}->{consumer}"
        try:
            ok, size = run_case(root, algorithm, ps, producer, consumer)
            decision = "pass" if ok else "fail"
            results.append({"case": ident, "algorithm": algorithm, "parameter_set": ps,
                            "producer": producer, "consumer": consumer, "artifact_bytes": size,
                            "decision": decision})
            if not ok:
                findings.append({"severity": "error", "code": "OPENSSL_INTEROP_MISMATCH", "message": ident})
        except Exception as exc:
            results.append({"case": ident, "algorithm": algorithm, "parameter_set": ps,
                            "producer": producer, "consumer": consumer, "decision": "fail", "reason": str(exc)})
            findings.append({"severity": "error", "code": "OPENSSL_INTEROP_EXECUTION_FAILED",
                             "message": f"{ident}: {exc}"})
    passed = sum(r["decision"] == "pass" for r in results)
    failed = len(results) - passed
    decision = "pass" if failed == 0 else "fail"
    report = {"schema_version": 1, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "decision": decision, "strict": args.strict,
              "summary": {"executed": len(results), "passed": passed, "failed": failed},
              "results": results, "findings": findings,
              "claim_boundary": "A pass demonstrates byte-compatible ML-KEM exchange and ML-DSA cross-verification between the native Rust implementation and the tested OpenSSL 3 provider implementation."}
    output = root / args.output
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = ["# OpenSSL Provider Interoperability Report", "", f"- Decision: **{decision}**",
             f"- Executed: {len(results)}", f"- Passed: {passed}", f"- Failed: {failed}", "",
             "| Algorithm | Parameter set | Producer | Consumer | Decision |",
             "|---|---|---|---|---|"]
    for result in results:
        lines.append(f"| {result['algorithm']} | `{result['parameter_set']}` | `{result['producer']}` | `{result['consumer']}` | **{result['decision']}** |")
    lines += ["", "## Findings", ""] + ([f"- **{f['code']}**: {f['message']}" for f in findings] if findings else ["No findings."])
    lines += ["", "## Claim boundary", "", report["claim_boundary"], ""]
    (output / "report.md").write_text("\n".join(lines))
    print(f"decision={decision}\nexecuted={len(results)}\npassed={passed}\nfailed={failed}\nreport={output / 'report.md'}")
    return 0 if decision == "pass" else 1

if __name__ == "__main__":
    raise SystemExit(main())

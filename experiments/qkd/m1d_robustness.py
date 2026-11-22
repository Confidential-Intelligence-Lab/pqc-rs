#!/usr/bin/env python3
"""M1.D diagnostic acceptance suite for circuit-level simulated BB84.

No security-qualified QKD: no finite-key proof, reconciliation, authenticated
classical discussion, device model, or general adversarial security argument.
The intentionally public fixture is NOT a production secret.
"""
import argparse
import math
from pathlib import Path
import subprocess
import sys
import tempfile


def call(argv, success=True):
    p = subprocess.run(argv, capture_output=True, text=True, check=False)
    if (p.returncode == 0) != success:
        raise AssertionError(
            f"unexpected process status for {argv[0]}: exit={p.returncode}\n"
            f"stdout={p.stdout[:900]}\nstderr={p.stderr[:900]}"
        )
    return p.stdout


def metrics(stdout):
    data = {}
    for line in stdout.splitlines():
        if line.startswith("BB84_") and "=" in line:
            k, v = line.split("=", 1)
            data[k] = v
    return data


def sweep(python, bb84, bits, seed):
    for intercept in (0, 25, 50, 75, 100):
        output = call([python, str(bb84), "--bits", str(bits), "--seed", str(seed),
                       "--intercept-percent", str(intercept)])
        d = metrics(output)
        sifted = int(d["BB84_SIFTED"])
        errors = int(d["BB84_ERRORS"])
        qber = float(d["BB84_QBER"])
        expected = intercept / 400.0
        assert int(d["BB84_TRANSMITTED"]) == bits
        assert 0 < sifted <= bits
        assert 0 <= errors <= sifted
        assert abs(qber - errors / sifted) < 1e-7
        # Generous statistical bound; this validates the attack diagnostic,
        # not the security or random-number quality of the simulator.
        sigma = math.sqrt(max(expected * (1 - expected), 0.0) / sifted)
        tolerance = max(0.035, 5 * sigma)
        if abs(qber - expected) > tolerance:
            raise AssertionError(f"attack={intercept}, qber={qber:.4f}, expected={expected:.4f}, tolerance={tolerance:.4f}")
        print(f"QKD_M1D_SWEEP intercept={intercept} sifted={sifted} errors={errors} qber={qber:.6f} expected={expected:.6f} status=PASS")


def fixtures(python, bb84, executable):
    with tempfile.TemporaryDirectory(prefix="qkd-m1d-") as tmp:
        root = Path(tmp)
        fixture = root / "paired.fixture"
        call([python, str(bb84), "--bits", "1024", "--seed", "20261120", "--output", str(fixture)])
        content = fixture.read_text(encoding="ascii")
        assert "provenance=cudaq-bb84-insecure-fixture" in content
        assert "errors=0" in content
        assert "secret_hex=" in content
        assert fixture.stat().st_mode & 0o777 == 0o600
        result = call([str(executable), str(fixture)])
        assert "QKD_M1C_CUDAQ_BB84_INTEGRATION_STATUS=PASS" in result
        assert "QKD_M1C_PROVENANCE=SIMULATION_FIXTURE_NOT_SECURE_QKD" in result

        changes = {
            "bad-provenance": content.replace("provenance=cudaq-bb84-insecure-fixture", "provenance=claimed-production-qkd"),
            "nonzero-errors": content.replace("errors=0", "errors=1"),
            "short-secret": content.replace("secret_hex=" + next(l.split("=",1)[1] for l in content.splitlines() if l.startswith("secret_hex=")), "secret_hex=00"),
            "missing-key-id": "\n".join(l for l in content.splitlines() if not l.startswith("key_id=")) + "\n",
            "duplicate-field": content + "errors=0\n",
            "invalid-count": content.replace("sifted=", "sifted=99999", 1),
        }
        for name, text in changes.items():
            path = root / f"reject-{name}.fixture"
            path.write_text(text, encoding="ascii")
            output = call([str(executable), str(path)], success=False)
            assert "QKD_M1C_CUDAQ_BB84_INTEGRATION_STATUS=PASS" not in output
            print(f"QKD_M1D_FIXTURE_REJECTION case={name} status=PASS")

        refused = root / "attack.fixture"
        call([python, str(bb84), "--bits", "1024", "--seed", "20261120",
              "--intercept-percent", "100", "--output", str(refused)], success=False)
        assert not refused.exists(), "attack diagnostic improperly exported a key fixture"
        print("QKD_M1D_ATTACK_KEY_EXPORT_REJECTION_STATUS=PASS")
        print("QKD_M1D_VALID_FIXTURE_MESSAGING_STATUS=PASS")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", required=True)
    ap.add_argument("--bb84", type=Path, required=True)
    ap.add_argument("--messaging", type=Path, required=True)
    ap.add_argument("--bits", type=int, default=2048)
    ap.add_argument("--seed", type=int, default=20261120)
    args = ap.parse_args()
    if args.bits < 1024:
        ap.error("require >= 1024 transmissions for diagnostic sweep")
    sweep(args.python, args.bb84, args.bits, args.seed)
    fixtures(args.python, args.bb84, args.messaging)
    print("QKD_M1D_PROTOCOL_ROBUSTNESS_STATUS=PASS")
    print("QKD_M1D_SECURITY_QUALIFIED=false")


if __name__ == "__main__":
    main()

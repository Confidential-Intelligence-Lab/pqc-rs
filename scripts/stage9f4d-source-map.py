#!/usr/bin/env python3
from __future__ import annotations
import argparse, subprocess
from pathlib import Path

SEARCHES = {
    "audit_multiply_challenge": ["multiply_challenge", "challenge_coefficient == 0"],
    "audit_sample_eta": ["sample_eta_poly", "UnsupportedEta"],
    "audit_sample_ball": ["sample_in_ball", "sample_in_ball_bytes"],
    "audit_rounding": ["power2round", "high_bits", "low_bits", "decompose"],
    "audit_encoding": ["encode_t0", "decode_t0", "encode_z", "decode_z"],
    "audit_sign_verify": ["sign_prepared", "verify_with_mu", "continue;"],
}

def grep(pattern: str, root: Path) -> str:
    result = subprocess.run(
        ["grep","-RIn","-F",pattern,str(root)],
        capture_output=True, text=True, check=False
    )
    return result.stdout.strip()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source_root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with args.output.open("w", encoding="utf-8") as stream:
        print("# Stage 9F-4D source-location candidates\n", file=stream)
        for target, patterns in SEARCHES.items():
            print(f"## `{target}`", file=stream)
            for pattern in patterns:
                print(f"### `{pattern}`", file=stream)
                matches = grep(pattern, args.source_root)
                if matches:
                    print("```text", file=stream)
                    print(matches, file=stream)
                    print("```", file=stream)
                else:
                    print("No match.", file=stream)
                print(file=stream)
    print(f"Wrote {args.output}")

if __name__ == "__main__":
    main()

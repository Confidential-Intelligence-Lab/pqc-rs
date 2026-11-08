#!/usr/bin/env python3
"""Generate reproducible structured SMAUG-T fuzz seeds."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGETS = (
    "secret_decode",
    "kem_decapsulate",
    "kem_encapsulate",
)
PREFIX = b"SMTF"


def descriptors():
    for mode in range(4):
        for region in range(4):
            for operation in range(4):
                for offset in (0, 1, 31, 63, 127, 255):
                    yield PREFIX + bytes((
                        mode,
                        region,
                        offset & 0xff,
                        (offset >> 8) & 0xff,
                        operation,
                        0xA5,
                    ))


def main():
    seeds = sorted(set(descriptors()))
    assert len(seeds) == 384
    assert all(len(seed) == 10 for seed in seeds)

    for target in TARGETS:
        directory = ROOT / "corpus" / target
        directory.mkdir(parents=True, exist_ok=True)

        created = 0
        for index, seed in enumerate(seeds):
            path = directory / f"structured_{index:04d}"
            if path.exists() and path.read_bytes() == seed:
                continue
            if path.exists():
                assert len(path.read_bytes()) == 6, (
                    f"Unexpected existing seed: {path}"
                )
            path.write_bytes(seed)
            created += 1

        for path in directory.glob("structured_*"):
            assert path.name in {
                f"structured_{index:04d}"
                for index in range(len(seeds))
            }, f"Unexpected structured seed: {path}"

        print(
            f"S5_5B_4B_CORPUS={target} "
            f"SEEDS={len(seeds)} UPDATED={created} STATUS=PASS"
        )

    print("S5_5B_4B_PREFIXED_CORPUS=PASS")


if __name__ == "__main__":
    main()

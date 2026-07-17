#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
mkdir -p .cargo
CONFIG=.cargo/config.toml
ALIAS='xtask = "run --manifest-path xtask/Cargo.toml --"'
if [[ ! -f "$CONFIG" ]]; then
  printf '[alias]\n%s\n' "$ALIAS" > "$CONFIG"
elif grep -Eq '^xtask[[:space:]]*=' "$CONFIG"; then
  echo "cargo xtask alias already present"
elif grep -Eq '^\[alias\][[:space:]]*$' "$CONFIG"; then
  python3 - "$CONFIG" "$ALIAS" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); alias = sys.argv[2]
lines = p.read_text().splitlines()
out=[]; inserted=False
for line in lines:
    out.append(line)
    if line.strip() == '[alias]' and not inserted:
        out.append(alias); inserted=True
p.write_text('\n'.join(out) + '\n')
PY
else
  printf '\n[alias]\n%s\n' "$ALIAS" >> "$CONFIG"
fi
cargo xtask compliance

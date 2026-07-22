#!/usr/bin/env bash
set -euo pipefail

# Rust nightly does not expose LLVM's UndefinedBehaviorSanitizer through
# `-Zsanitizer`. Miri is this repository's executable undefined-behavior gate;
# ASan provides the complementary native memory-safety screen. Keep this
# compatibility entry point so older automation records the limitation instead
# of failing with an unsupported rustc flag or claiming that UBSan ran.
echo "UNSUPPORTED: rustc does not provide -Zsanitizer=undefined; Miri is the undefined-behavior gate."

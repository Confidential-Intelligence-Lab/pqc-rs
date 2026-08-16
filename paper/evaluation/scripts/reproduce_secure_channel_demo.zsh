#!/bin/zsh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

CARGO="$(command -v cargo)"
RUSTC="$(command -v rustc)"

E4_FROZEN="paper/evaluation/raw/secure-channel/e4/negative_matrix-results.psv"
E5_FROZEN="paper/evaluation/raw/secure-channel/e5/loopback_tcp-results.psv"
E6_FROZEN="paper/evaluation/raw/secure-channel/e6/adverse_schedule-results.psv"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pqc-e7.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

BEFORE_STATUS="$TMP_DIR/status-before.txt"
AFTER_STATUS="$TMP_DIR/status-after.txt"

REFERENCE_OUT="$TMP_DIR/reference-workflow.txt"
E4_OUT="$TMP_DIR/e4-negative-matrix.txt"
E5_OUT="$TMP_DIR/e5-loopback-tcp.txt"
E6_OUT="$TMP_DIR/e6-adverse-schedule.txt"

fail() {
    print -u2 -- "E7: FAIL — $1"
    exit 1
}

require_file() {
    test -f "$1" || fail "required file missing: $1"
}

count_matches() {
    local pattern="$1"
    local file="$2"
    grep -cE "$pattern" "$file" 2>/dev/null || true
}

echo "===== interpreters and toolchain ====="
echo "shell=/bin/zsh"
echo "zsh_version=$ZSH_VERSION"
echo "cargo=$CARGO"
"$CARGO" --version
echo "rustc=$RUSTC"
"$RUSTC" --version

echo
echo "===== repository ====="
echo "revision=$(git rev-parse HEAD)"
echo "branch=$(git branch --show-current)"

require_file "$E4_FROZEN"
require_file "$E5_FROZEN"
require_file "$E6_FROZEN"

git status --porcelain=v1 > "$BEFORE_STATUS"

echo
echo "===== reference workflow ====="
"$CARGO" test \
    -p pqc-rs-secure-channel \
    --test reference_workflow \
    -- --nocapture \
    >"$REFERENCE_OUT" 2>&1 \
    || {
        cat "$REFERENCE_OUT"
        fail "reference workflow execution failed"
    }

grep -q \
    'test reference_workflow_succeeds_for_all_registered_secure_channel_profiles ... ok' \
    "$REFERENCE_OUT" \
    || {
        cat "$REFERENCE_OUT"
        fail "reference workflow success record missing"
    }

echo "REFERENCE WORKFLOW: PASS"

echo
echo "===== E4 negative matrix ====="
"$CARGO" test \
    -p pqc-rs-secure-channel \
    --test negative_matrix \
    -- --nocapture \
    >"$E4_OUT" 2>&1 \
    || {
        cat "$E4_OUT"
        fail "E4 negative matrix execution failed"
    }

E4_RUNTIME_ROWS="$(count_matches '^N[0-9]+\|' "$E4_OUT")"
E4_RUNTIME_PASS="$(count_matches '^N[0-9]+\|.*\|PASS$' "$E4_OUT")"

test "$E4_RUNTIME_ROWS" -eq 14 \
    || {
        cat "$E4_OUT"
        fail "E4 runtime row count=$E4_RUNTIME_ROWS, expected 14"
    }

test "$E4_RUNTIME_PASS" -eq 14 \
    || {
        cat "$E4_OUT"
        fail "E4 runtime PASS count=$E4_RUNTIME_PASS, expected 14"
    }

echo "E4 NEGATIVE MATRIX: PASS"

echo
echo "===== E5 loopback TCP ====="
"$CARGO" test \
    -p pqc-rs-secure-channel \
    --test loopback_tcp \
    -- --nocapture \
    >"$E5_OUT" 2>&1 \
    || {
        cat "$E5_OUT"
        fail "E5 loopback TCP execution failed"
    }

E5_RUNTIME_ROWS="$(count_matches '^E5\|' "$E5_OUT")"
E5_RUNTIME_PASS="$(count_matches '^E5\|.*\|PASS$' "$E5_OUT")"

test "$E5_RUNTIME_ROWS" -eq 3 \
    || {
        cat "$E5_OUT"
        fail "E5 runtime row count=$E5_RUNTIME_ROWS, expected 3"
    }

test "$E5_RUNTIME_PASS" -eq 3 \
    || {
        cat "$E5_OUT"
        fail "E5 runtime PASS count=$E5_RUNTIME_PASS, expected 3"
    }

for profile in MLKEM768 MLKEM1024 MLKEM768-X25519; do
    count="$(count_matches "^E5\\|${profile}\\|" "$E5_OUT")"
    test "$count" -eq 1 \
        || fail "E5 runtime profile ${profile} count=$count, expected 1"
done

echo "E5 LOOPBACK TCP: PASS"

echo
echo "===== E6 adverse schedules ====="
"$CARGO" test \
    -p pqc-rs-secure-channel \
    --test adverse_schedule \
    -- --nocapture \
    >"$E6_OUT" 2>&1 \
    || {
        cat "$E6_OUT"
        fail "E6 adverse-schedule execution failed"
    }

E6_RUNTIME_ROWS="$(count_matches '^E6\|' "$E6_OUT")"
E6_RUNTIME_PASS="$(count_matches '^E6\|.*\|PASS$' "$E6_OUT")"

test "$E6_RUNTIME_ROWS" -eq 18 \
    || {
        cat "$E6_OUT"
        fail "E6 runtime row count=$E6_RUNTIME_ROWS, expected 18"
    }

test "$E6_RUNTIME_PASS" -eq 18 \
    || {
        cat "$E6_OUT"
        fail "E6 runtime PASS count=$E6_RUNTIME_PASS, expected 18"
    }

for schedule in S0 S1 S2 S3 S4 S5; do
    count="$(count_matches "^E6\\|${schedule}\\|" "$E6_OUT")"
    test "$count" -eq 3 \
        || fail "E6 runtime schedule ${schedule} count=$count, expected 3"
done

for profile in MLKEM768 MLKEM1024 MLKEM768-X25519; do
    count="$(count_matches "^E6\\|[^|]+\\|${profile}\\|" "$E6_OUT")"
    test "$count" -eq 6 \
        || fail "E6 runtime profile ${profile} count=$count, expected 6"
done

E6_BAD_SEQUENCE="$(
    grep '^E6|' "$E6_OUT" |
    grep -vc \
        'client_tx_sequence=1|client_rx_sequence=1|server_tx_sequence=1|server_rx_sequence=1|PASS$' \
        || true
)"

test "$E6_BAD_SEQUENCE" -eq 0 \
    || fail "E6 runtime contains $E6_BAD_SEQUENCE invalid sequence record(s)"

echo "E6 ADVERSE SCHEDULE MATRIX: PASS"

echo
echo "===== frozen evidence verification ====="

E4_FROZEN_ROWS="$(count_matches '^N[0-9]+\|' "$E4_FROZEN")"
E4_FROZEN_PASS="$(count_matches '^N[0-9]+\|.*\|PASS$' "$E4_FROZEN")"

test "$E4_FROZEN_ROWS" -eq 14 \
    || fail "E4 frozen row count=$E4_FROZEN_ROWS, expected 14"
test "$E4_FROZEN_PASS" -eq 14 \
    || fail "E4 frozen PASS count=$E4_FROZEN_PASS, expected 14"

E5_FROZEN_ROWS="$(count_matches '^E5\|' "$E5_FROZEN")"
E5_FROZEN_PASS="$(count_matches '^E5\|.*\|PASS$' "$E5_FROZEN")"

test "$E5_FROZEN_ROWS" -eq 3 \
    || fail "E5 frozen row count=$E5_FROZEN_ROWS, expected 3"
test "$E5_FROZEN_PASS" -eq 3 \
    || fail "E5 frozen PASS count=$E5_FROZEN_PASS, expected 3"

for profile in MLKEM768 MLKEM1024 MLKEM768-X25519; do
    count="$(count_matches "^E5\\|${profile}\\|" "$E5_FROZEN")"
    test "$count" -eq 1 \
        || fail "E5 frozen profile ${profile} count=$count, expected 1"
done

E6_FROZEN_ROWS="$(count_matches '^E6\|' "$E6_FROZEN")"
E6_FROZEN_PASS="$(count_matches '^E6\|.*\|PASS$' "$E6_FROZEN")"

test "$E6_FROZEN_ROWS" -eq 18 \
    || fail "E6 frozen row count=$E6_FROZEN_ROWS, expected 18"
test "$E6_FROZEN_PASS" -eq 18 \
    || fail "E6 frozen PASS count=$E6_FROZEN_PASS, expected 18"

for schedule in S0 S1 S2 S3 S4 S5; do
    count="$(count_matches "^E6\\|${schedule}\\|" "$E6_FROZEN")"
    test "$count" -eq 3 \
        || fail "E6 frozen schedule ${schedule} count=$count, expected 3"
done

for profile in MLKEM768 MLKEM1024 MLKEM768-X25519; do
    count="$(count_matches "^E6\\|[^|]+\\|${profile}\\|" "$E6_FROZEN")"
    test "$count" -eq 6 \
        || fail "E6 frozen profile ${profile} count=$count, expected 6"
done

E6_FROZEN_BAD_SEQUENCE="$(
    grep '^E6|' "$E6_FROZEN" |
    grep -vc \
        'client_tx_sequence=1|client_rx_sequence=1|server_tx_sequence=1|server_rx_sequence=1|PASS$' \
        || true
)"

test "$E6_FROZEN_BAD_SEQUENCE" -eq 0 \
    || fail "E6 frozen evidence contains $E6_FROZEN_BAD_SEQUENCE invalid sequence record(s)"

echo "FROZEN EVIDENCE VERIFICATION: PASS"

echo
echo "===== repository hygiene ====="

git status --porcelain=v1 > "$AFTER_STATUS"

cmp -s "$BEFORE_STATUS" "$AFTER_STATUS" \
    || {
        echo "----- before -----" >&2
        cat "$BEFORE_STATUS" >&2
        echo "----- after -----" >&2
        cat "$AFTER_STATUS" >&2
        fail "repository state changed during E7 reproduction"
    }

git diff --quiet \
    || fail "tracked unstaged files changed during E7 reproduction"

git diff --cached --quiet \
    || fail "staged files changed during E7 reproduction"

echo "REPOSITORY HYGIENE: PASS"

echo
echo "===== E7 summary ====="
echo "REFERENCE WORKFLOW: PASS"
echo "E4 NEGATIVE MATRIX: PASS"
echo "E5 LOOPBACK TCP: PASS"
echo "E6 ADVERSE SCHEDULE MATRIX: PASS"
echo "FROZEN EVIDENCE VERIFICATION: PASS"
echo "REPOSITORY HYGIENE: PASS"
echo
echo "SECURE-CHANNEL REPRODUCIBILITY DEMO: PASS"

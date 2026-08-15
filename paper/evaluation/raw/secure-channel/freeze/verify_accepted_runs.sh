#!/bin/sh
set -eu

BASE="paper/evaluation/raw/secure-channel"
RUNS="$BASE/accepted-runs"
EXPECTED_REVISION="e0610df9d070fe93a4e016161358c945289dd28d"

failure=0
count=0

while IFS= read -r run_id; do
    test -n "$run_id" || continue

    count=$((count + 1))
    dir="$RUNS/$run_id"

    echo "===== $run_id ====="

    if test ! -d "$dir"; then
        echo "FAIL: missing run directory"
        failure=1
        echo
        continue
    fi

    revision="$(sed -n 's/^revision=//p' "$dir/RUN.txt" | head -n 1)"
    exit_status="$(sed -n 's/^benchmark_exit_status=//p' "$dir/RUN.txt" | head -n 1)"
    status="$(sed -n 's/^status=//p' "$dir/RUN.txt" | tail -n 1)"

    analyses="$(
        grep -c '^Benchmarking secure_channel/.*/.*: Analyzing' \
            "$dir/criterion-output.txt" || true
    )"

    estimates="$(
        find "$dir/criterion" -path '*/new/estimates.json' -type f |
            wc -l |
            tr -d ' '
    )"

    ac_observations="$(
        grep -c "Now drawing from 'AC Power'" "$dir/RUN.txt" || true
    )"

    battery_observations="$(
        grep -c "Now drawing from 'Battery Power'" "$dir/RUN.txt" || true
    )"

    low_power_nonzero="$(
        awk '
            /^===== pre-run low-power configuration =====/ { in_section=1; next }
            /^===== post-run low-power configuration =====/ { in_section=1; next }
            /^=====/ { if (in_section) in_section=0 }
            in_section && $1 == "lowpowermode" && $2 != "0" { count++ }
            END { print count + 0 }
        ' "$dir/RUN.txt"
    )"

    printf 'revision=%s\n' "$revision"
    printf 'exit_status=%s\n' "$exit_status"
    printf 'status=%s\n' "$status"
    printf 'analyses=%s\n' "$analyses"
    printf 'new_estimates=%s\n' "$estimates"
    printf 'ac_observations=%s\n' "$ac_observations"
    printf 'battery_observations=%s\n' "$battery_observations"
    printf 'low_power_nonzero=%s\n' "$low_power_nonzero"

    if test "$revision" != "$EXPECTED_REVISION"; then
        echo "FAIL: revision mismatch"
        failure=1
    fi

    if test "$exit_status" != "0"; then
        echo "FAIL: benchmark exit status is not zero"
        failure=1
    fi

    if test "$status" != "accepted"; then
        echo "FAIL: run is not marked accepted"
        failure=1
    fi

    if test "$analyses" -ne 24; then
        echo "FAIL: expected 24 analyzed cases"
        failure=1
    fi

    if test "$estimates" -ne 24; then
        echo "FAIL: expected 24 new estimate files"
        failure=1
    fi

    if test "$ac_observations" -lt 2; then
        echo "FAIL: expected at least pre-run and post-run AC observations"
        failure=1
    fi

    if test "$battery_observations" -ne 0; then
        echo "FAIL: battery-power observation present"
        failure=1
    fi

    if test "$low_power_nonzero" -ne 0; then
        echo "FAIL: nonzero low-power mode observed"
        failure=1
    fi

    echo
done < "$BASE/freeze/ACCEPTED_RUNS.txt"

if test "$count" -ne 5; then
    echo "FAIL: expected exactly 5 accepted runs, found $count"
    failure=1
fi

if test "$failure" -ne 0; then
    echo "DATASET FREEZE VERIFICATION: FAIL"
    exit 1
fi

echo "DATASET FREEZE VERIFICATION: PASS"
echo "accepted_runs=5"
echo "cases_per_run=24"
echo "accepted_distributions=120"
echo "revision=$EXPECTED_REVISION"

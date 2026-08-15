# Secure-Channel E2 Dataset Freeze

## Accepted Dataset

The accepted controlled-AC E2 dataset consists of exactly five independent
Criterion runs:

~~~text
2026-08-15-m4-ac-run04
2026-08-15-m4-ac-run06
2026-08-15-m4-ac-run07
2026-08-15-m4-ac-run08
2026-08-15-m4-ac-run09
~~~

Each accepted run contains 24 benchmark cases:

~~~text
8 operations x 3 secure-channel profiles = 24 cases
~~~

The frozen dataset therefore contains:

~~~text
5 runs x 24 cases = 120 accepted benchmark distributions
~~~

## Common Revision

All accepted runs were collected from:

~~~text
e0610df9d070fe93a4e016161358c945289dd28d
~~~

This revision differs from the earlier environment-documentation baseline only
by evaluation documentation/provenance changes; the benchmark implementation
used for the accepted runs remained unchanged.

## Acceptance Requirements

A run is accepted only when all of the following hold:

1. the recorded revision matches the frozen benchmark revision;
2. pre-run power is AC;
3. post-run power is AC;
4. low-power mode is disabled;
5. `cargo bench` exits with status 0;
6. all 24 benchmark cases reach Criterion analysis;
7. all 24 `new/estimates.json` artifacts are retained;
8. the run is explicitly marked `status=accepted`.

Run inclusion was determined before cross-run performance values were
extracted or aggregated.

## Non-Accepted Runs

Other retained runs are excluded from the frozen dataset:

~~~text
run01  excluded: complete-run AC continuity not established
run02  excluded: battery power before and after
run03  not accepted: benchmark exit-status provenance defect
run05  excluded: incomplete console execution record and artifact provenance mismatch
~~~

These runs remain retained for auditability but are not used in paper-facing
aggregate statistics.

## Statistical Boundary

The dataset freeze precedes numerical extraction.

Criterion within-run uncertainty and between-run replication variability must
be analyzed separately. No accepted run may be removed or replaced based on
its performance values after this freeze unless a new, independently
documented integrity defect is discovered.

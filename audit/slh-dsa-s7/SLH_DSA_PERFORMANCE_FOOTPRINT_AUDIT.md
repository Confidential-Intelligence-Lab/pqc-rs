# SLH-DSA S7 performance and footprint audit

## Scope

This audit closes S7 by combining reproducible performance measurements with
the footprint evidence established during S6.

The performance baseline covers all twelve FIPS 205 SLH-DSA parameter sets and
five public operations:

- deterministic key generation from seed;
- deterministic Pure SLH-DSA signing;
- Pure SLH-DSA verification;
- deterministic HashSLH-DSA signing;
- HashSLH-DSA verification.

HashSLH-DSA uses SHA2-256 as the representative prehash, matching the S6 memory
campaign.

The baseline is an engineering characterization of the current implementation
and platform. It is not a cross-platform performance guarantee or a claim of
performance superiority.

## Reproducibility

The authoritative baseline was produced from commit:

```text
f0b7591bfdd41b02a1cbe5424045761ce4b5c35d
Environment:

Platform: Darwin arm64
CPU: Apple M4
Logical CPUs: 10
Memory: 24 GiB
rustc: 1.89.0
LLVM: 20.1.7
cargo: 1.89.0

The performance policy gate classified fifteen benchmark groups successfully.

The SLH-DSA campaign produced exactly:

12 parameter sets × 5 operations = 60 Criterion measurements

Criterion sample size is 10. Key generation uses an extended measurement
window and signing uses a 20-second target measurement window to accommodate
the higher cost of the s parameter sets.

Performance baseline

The complete machine-readable baseline is recorded in:

audit/slh-dsa-s7/SLH_DSA_PERFORMANCE_BASELINE.csv

The human-readable summary is recorded in:

audit/slh-dsa-s7/SLH_DSA_PERFORMANCE_SUMMARY.md

Representative median results:

Parameter set	KeyGen	Pure sign	Pure verify
SLH-DSA-SHA2-128s	65.850 ms	916.553 ms	522.523 us
SLH-DSA-SHA2-128f	1.039 ms	45.177 ms	1.496 ms
SLH-DSA-SHA2-192s	97.527 ms	1.488 s	755.274 us
SLH-DSA-SHA2-192f	1.530 ms	70.213 ms	2.141 ms
SLH-DSA-SHA2-256s	65.126 ms	1.253 s	1.104 ms
SLH-DSA-SHA2-256f	4.068 ms	146.656 ms	2.194 ms
SLH-DSA-SHAKE-128s	84.416 ms	1.148 s	603.336 us
SLH-DSA-SHAKE-128f	1.321 ms	57.734 ms	1.850 ms
SLH-DSA-SHAKE-192s	123.973 ms	1.858 s	902.780 us
SLH-DSA-SHAKE-192f	1.939 ms	88.213 ms	2.638 ms
SLH-DSA-SHAKE-256s	81.346 ms	1.538 s	1.263 ms
SLH-DSA-SHAKE-256f	5.084 ms	181.133 ms	2.725 ms
s versus f tradeoff

The measured results expose the intended SLH-DSA parameter-set tradeoff.

The f variants substantially reduce key-generation and signing latency. For
example:

SHA2-128:
  Pure sign 128s = 916.553 ms
  Pure sign 128f = 45.177 ms
  ratio ≈ 20.3×

SHA2-192:
  Pure sign 192s = 1.488 s
  Pure sign 192f = 70.213 ms
  ratio ≈ 21.2×

The s variants, however, produce smaller signatures and generally verify
faster.

The choice between s and f should therefore be treated as a system-level
latency/footprint tradeoff rather than as interchangeable security-equivalent
implementations with similar operational characteristics.

Pure versus HashSLH

For the short benchmark message and representative SHA2-256 prehash, Pure and
HashSLH signing times are close across all parameter sets.

Examples:

SHA2-128s:
  Pure sign = 916.553 ms
  Hash sign = 915.994 ms

SHAKE-192s:
  Pure sign = 1.858 s
  Hash sign = 1.858 s

The dominant cost in these measurements is the SLH-DSA signature computation,
not the representative message prehash.

This result should not be interpreted as an exhaustive characterization of
HashSLH overhead for arbitrary message sizes or every standardized prehash
algorithm.

Encoded footprint

Across the twelve parameter sets:

key-generation seed size is 3n;
public-key size is 2n;
private-key size is 4n;
signatures range from 7,856 bytes to 49,856 bytes.

SHA2 and SHAKE variants with equivalent structural parameters have identical
encoded object sizes.

The f parameter sets achieve their lower signing latency partly by accepting
larger signatures.

Heap footprint

The S6 bounded heap campaign measured all twelve parameter sets across the same
five public-operation classes.

Maximum observed peak live heap:

Operation	Maximum peak live heap
key generation from seed	416 B
Pure deterministic signing	99,864 B
Pure verification	152 B
HashSLH deterministic signing	99,879 B
HashSLH verification	167 B

Signing is dominated by the returned signature allocation. Verification
returns with zero tracked live heap in the measured campaign.

Stack structure

The maximum simultaneously active recursive calls established during S6 are:

FORS node recursion: 15
XMSS node recursion: 10

Compiler-emitted optimized fixed stack frames were:

Function	Fixed frame
pqc_slh_dsa::fors::node	248 B
pqc_slh_dsa::fors::leaf	296 B
pqc_slh_dsa::xmss::node	232 B
pqc_slh_dsa::xmss::parent_node	120 B

The recursive node() frame contributions are bounded by:

FORS: 15 × 248 B = 3,720 B
XMSS: 10 × 232 B = 2,320 B

These are fixed recursive-frame contributions, not measurements of total peak
thread-stack consumption.

Interpretation

The implementation exhibits the expected SLH-DSA systems tradeoffs:

f variants are substantially faster for key generation and signing;
s variants minimize signature size and generally verify faster;
SHAKE variants are generally slower than structurally equivalent SHA2
variants on the measured Apple M4 platform;
Pure and representative HashSLH signing have similar cost for the short
benchmark message;
verification remains orders of magnitude faster than signing for the s
variants;
memory behavior remains bounded and modest relative to signature size.

The measurements are intended to support deployment decisions and regression
tracking, not to establish cross-platform or cross-library superiority.

Result

S7: PASS within the documented performance and footprint scope.

All twelve FIPS 205 parameter sets are covered by reproducible latency
measurements and have corresponding encoded-size, heap, recursion, and
compiler-frame evidence.

The next work package is S8: documentation, release-readiness, and public-facing
project presentation.

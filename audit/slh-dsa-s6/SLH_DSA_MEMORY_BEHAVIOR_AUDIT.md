# SLH-DSA S6 memory-behavior audit

## Scope

This audit consolidates structural, compiler-emitted, and runtime memory
evidence for the SLH-DSA implementation across all twelve FIPS 205 parameter
sets.

The evidence covers:

- parameter-dependent key and signature geometry;
- FORS and XMSS recursive tree structure;
- compiler-emitted fixed stack-frame sizes for optimized production routines;
- runtime heap-allocation behavior for public key generation, signing, and
  verification paths;
- bounded dynamic-analysis gates in CI.

This audit does not claim to measure total peak thread-stack consumption.

## Parameter geometry

The twelve FIPS 205 parameter sets reduce to six structural geometries because
the paired SHA2 and SHAKE variants share identical values of `n`, `h`, `d`,
`hp`, `a`, `k`, and encoded object sizes.

Across all parameter sets:

- public-key size is `2n`;
- private-key size is `4n`;
- key-generation seed size is `3n`;
- the largest signature is 49,856 bytes for the 256f geometry.

The maximum FORS tree height is 14 and the maximum XMSS subtree height is 9.

## Recursive stack structure

The production FORS and XMSS node routines recursively descend their respective
tree heights.

The analytical maximum simultaneously active recursive node invocations are:

```text
FORS: 15
XMSS: 10
The extra invocation accounts for the height-zero frame.

Optimized fixed stack frames

The Linux/ELF optimized stack audit uses Rust nightly with:

-Z emit-stack-sizes
-C force-frame-pointers=yes
-C debuginfo=2

Compiler-emitted stack metadata recovered:

Function	Fixed frame
pqc_slh_dsa::fors::node	248 B
pqc_slh_dsa::fors::leaf	296 B
pqc_slh_dsa::xmss::node	232 B
pqc_slh_dsa::xmss::parent_node	120 B

The corresponding recursive node-frame contributions are bounded by:

FORS: 15 * 248 B = 3,720 B
XMSS: 10 * 232 B = 2,320 B

These values cover the simultaneously active recursive node() frames only.
They are not total runtime stack measurements. Callers, leaf routines, WOTS,
hash routines, alignment, spills, and other callee frames may contribute
additional stack usage.

Runtime heap behavior

The bounded heap audit instruments the process global allocator and records:

allocation count;
deallocation count;
cumulative allocated bytes;
cumulative deallocated bytes;
live bytes at operation return;
peak simultaneously live bytes.

The audit covers all twelve parameter sets and five public-operation classes:

12 parameter sets * 5 operations = 60 measurements

The measured operations are:

deterministic key generation from a parameter-bound seed;
deterministic Pure SLH-DSA signing;
Pure SLH-DSA verification;
deterministic HashSLH-DSA signing using SHA2-256 prehash;
HashSLH-DSA verification using SHA2-256 prehash.

The allocator accounting fails closed if cumulative allocation and deallocation
totals are inconsistent with live-byte accounting.

Maximum observed peak live heap:

Operation	Maximum peak live heap
key generation from seed	416 B
Pure deterministic signing	99,864 B
Pure verification	152 B
HashSLH deterministic signing	99,879 B
HashSLH verification	167 B

Signing retains only the returned signature allocation at the measurement
boundary. Verification returns with zero tracked live heap.

SHA2 and SHAKE variants with identical structural parameters produced identical
allocation measurements.

The HashSLH memory campaign uses SHA2-256 as the representative prehash for
memory-behavior measurement; it is not an exhaustive all-prehash footprint
campaign.

Dynamic-analysis closure

Public Dynamic analysis run 35166990327 completed successfully with all jobs
green, including:

repository Miri;
bounded SLH-DSA Miri;
broad workspace AddressSanitizer;
bounded SLH-DSA AddressSanitizer;
SLH-DSA optimized stack-size audit;
SLH-DSA heap audit.

The broad workspace ASan gate excludes SLH-DSA's exhaustive suites because
SLH-DSA has an independent bounded ASan campaign. This keeps the scopes
explicit and prevents duplicate exhaustive SLH execution from exceeding the
workflow budget.

Result

S6.4: PASS within the documented memory-behavior claims.

The implementation has bounded recursive tree depth, reproducible optimized
fixed-frame evidence, and deterministic all-parameter-set heap measurements
for the evaluated public operations.

The evidence does not constitute a proof of total stack consumption, absence
of all memory-safety defects, or cryptographic security.

# SLH-DSA S6 stack-behavior audit

## Scope

This audit records analytical recursion bounds and compiler-emitted fixed
stack-frame metadata for the recursive SLH-DSA FORS and XMSS tree routines.

The evidence does not claim to measure total peak thread-stack usage.

## Analytical recursion bounds

The FIPS 205 parameter geometry is derived directly from
`SlhDsaParameterSet::parameters()`.

Across all twelve standardized parameter sets:

- maximum FORS tree height `a` is 14;
- maximum simultaneously active `fors::node` invocations are therefore 15;
- maximum XMSS tree height `hp` is 9;
- maximum simultaneously active `xmss::node` invocations are therefore 10.

The additional invocation accounts for the height-zero node frame.

## Compiler-emitted stack sizes

The dedicated Linux/ELF audit builds the optimized stack harness using:

```text
-Z emit-stack-sizes
-C force-frame-pointers=yes
-C debuginfo=2
The stack-size metadata is decoded with the LLVM tools distributed with the
active Rust nightly toolchain.

Public Dynamic analysis run 35146913636, job 104965242776, recovered:

Function	Fixed frame
pqc_slh_dsa::fors::node	248 B
pqc_slh_dsa::fors::leaf	296 B
pqc_slh_dsa::xmss::node	232 B
pqc_slh_dsa::xmss::parent_node	120 B

The recursive node-frame contributions are therefore bounded by:

FORS: 15 * 248 B = 3,720 B
XMSS: 10 * 232 B = 2,320 B

These values bound only the simultaneously active recursive node() frames.
They are not measurements of total peak stack consumption. Leaf routines,
hash functions, WOTS routines, callers, compiler spills, alignment, and other
callee frames can contribute additional stack usage.

Result

S6.4c: PASS within the documented compiler-emitted fixed-frame claim.

The evidence establishes bounded recursive depth and optimized fixed-frame
sizes for the production FORS and XMSS node routines on the recorded
Linux/x86-64 nightly toolchain. Runtime peak-stack measurement, if required,
is a separate assurance measurement.

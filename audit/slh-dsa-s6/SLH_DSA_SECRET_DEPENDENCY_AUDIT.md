# SLH-DSA Source-Level Secret-Dependency Audit

## Scope

This audit records the S6.2 source-level secret-dependency review for the
PQC-rs SLH-DSA implementation.

Reviewed implementation boundaries:

- `crates/pqc-slh-dsa/src/api.rs`
- `crates/pqc-slh-dsa/src/hash.rs`
- `crates/pqc-slh-dsa/src/wots.rs`
- `crates/pqc-slh-dsa/src/fors.rs`
- `crates/pqc-slh-dsa/src/xmss.rs`
- `crates/pqc-slh-dsa/src/hypertree.rs`

The audit distinguishes secret-dependent execution from execution that varies
with public parameters or message/transcript-derived values. It is a
source-level engineering review and is not a formal constant-time proof.

## Dependency Classes

Secret inputs include:

- `SK.seed`
- `SK.prf`
- optional signing randomness
- WOTS+ and FORS secret values derived from `SK.seed`

Public or transcript-derived inputs include:

- parameter set and its structural parameters
- message and context
- `H_msg` output
- WOTS+ chain lengths
- FORS indices
- XMSS tree and leaf positions
- hypertree layer, tree, and leaf positions

## Findings

### S6.2c-F1 — SLH-DSA PRF

**Result: PASS**

`SK.seed` is supplied as cryptographic input to the SLH-DSA PRF. Source
review found no branch condition, loop bound, allocation size, or memory index
derived from the bytes of `SK.seed`.

### S6.2c-F2 — SLH-DSA PRF_msg

**Result: PASS**

`SK.prf` and optional randomness are supplied as cryptographic inputs to
`PRF_msg`. SHA-256/SHA-512 selection is controlled by the public parameter
set. Source review found no control-flow or memory-index decision derived
from secret input bytes.

### S6.2c-F3 — Private-Key Partitioning

**Result: PASS**

Private-key slices are selected using offsets derived from the public
parameter-set value `n`. Memory addresses into secret storage therefore vary
with the public parameter set, not with secret-key contents.

### S6.2c-F4 — WOTS+ Signing

**Result: PASS**

WOTS+ signing is intentionally public-variable-time. Per-chain hash counts
derive from message-dependent WOTS+ chain lengths. `SK.seed` determines
cryptographic chain values but does not determine chain counts.

### S6.2c-F5 — FORS Signing

**Result: PASS**

FORS tree and leaf selections derive from indices extracted from the message
digest. Authentication-path positions and left/right reconstruction decisions
derive from those indices. Secret FORS values do not select control flow or
memory positions.

### S6.2c-F6 — XMSS Signing

**Result: PASS**

XMSS traversal is bounded by public parameter-set dimensions. Leaf and sibling
positions and left/right decisions derive from the transcript-derived leaf
index. No secret-key byte was identified as controlling traversal.

### S6.2c-F7 — Hypertree Signing

**Result: PASS**

Hypertree traversal executes the public parameter-set-defined number of
layers. Tree and leaf transitions derive from transcript-derived positions.
Secret-key contents do not determine the layer count or position transitions.

### S6.2c-F8 — Secret-Dependent Control Flow or Indexing

**Result: NONE FOUND BY SOURCE REVIEW**

The reviewed Rust source contains no identified branch condition, loop bound,
array index, memory-address selection, or allocation size whose value derives
from secret-key bytes or secret optional-randomness bytes.

This result is limited to source-level dependency analysis. It does not
establish a formal constant-time guarantee and does not establish that
optimized generated machine code preserves the same dependency properties.

## Claim Boundary

The complete SLH-DSA signing operation is not claimed to execute in fixed
time. WOTS+, FORS, XMSS, and hypertree work may vary according to public
parameters and message/transcript-derived values.

The assurance claim established by this audit is narrower: source review found
no additional control-flow or memory-access variation attributable to secret
input values.

Generated-code inspection, statistical timing analysis, and dynamic
secret-dependency testing are independent subsequent assurance gates.

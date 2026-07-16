# Constant-Time Review Checklist

## Source review

- [ ] Secret-bearing values are identified.
- [ ] Public and transcript-derived values are identified.
- [ ] No secret-dependent `if`, `match`, `while`, or early return.
- [ ] No secret-dependent loop bounds.
- [ ] No secret-indexed array, slice, vector, or table access.
- [ ] No secret-dependent allocation or deallocation.
- [ ] No secret-dependent error path.
- [ ] Division and remainder on secret values are absent or justified.
- [ ] Arithmetic overflow behavior is explicit.
- [ ] Rejection sampling is documented separately.

## Functional validation

- [ ] Unit tests pass.
- [ ] Workspace tests pass.
- [ ] Clippy passes with warnings denied.
- [ ] Known-answer tests pass.
- [ ] ACVP vectors pass where available.
- [ ] Serialization round trips pass.
- [ ] Malformed-input behavior is tested.

## Timing validation

- [ ] End-to-end fixed-versus-varying timing screen completed.
- [ ] Per-primitive timing localization completed.
- [ ] Matched-distribution control completed.
- [ ] Rejection-loop timing characterized.
- [ ] Fixed-key versus varying-key comparison completed.
- [ ] Residual timing after conditioning completed.
- [ ] Results archived with compiler and platform metadata.

## Generated-code review

- [ ] Optimized machine code recovered.
- [ ] Critical symbols or audit wrappers recovered.
- [ ] Conditional branches inventoried.
- [ ] Conditional selects inventoried.
- [ ] Division instructions inventoried.
- [ ] Table-lookup instructions inventoried.
- [ ] Indexed-memory candidates reviewed.
- [ ] Secret-dependent instructions mapped to source.
- [ ] Finding register completed.
- [ ] No unresolved secret-dependent control flow.
- [ ] No unresolved secret-indexed memory.

## Portability

- [ ] Apple ARM64 reviewed.
- [ ] Linux ARM64 reviewed.
- [ ] x86-64 baseline reviewed.
- [ ] x86-64 optimized path reviewed.
- [ ] Compiler-version changes trigger re-review.

## Release record

- [ ] Repository commit recorded.
- [ ] rustc version recorded.
- [ ] LLVM version recorded.
- [ ] target triple recorded.
- [ ] compiler flags recorded.
- [ ] reviewer recorded.
- [ ] review date recorded.
- [ ] limitations documented.
- [ ] public claim wording reviewed.

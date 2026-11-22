# S5.D-3: Bounded local Cascade reconciliation experiment

**Disposition:** Research-only, unqualified. No QKD PSK or HPKE export.

## Precommitted disclosure ceiling

Frozen S5.C profile: `n=k_min=16384`, `Q_tol=0.02`, `M_max=100000`,
`epsilon_sec=epsilon_cor=1e-10`, `ell_requested=256`. S5.D-3 caps
Cascade at **4800 parity pairs**, charging **two secret-dependent parity bits
per pair**, hence **9600 bits maximum parity disclosure** on the accepted
path. The independent 64-bit confirmation collision test is accounted for
through the TLGR correctness term, not automatically charged a second time.
All claims of leakage completeness remain provisional until transcript
and interactive-history conditioning are proved.

Using unchanged TLGR Eq. (2) numerical evaluator and the *predeclared* `k_min`,
this corresponds to approximately 457 candidate output bits, above the
requested 256. This is numerical feasibility, not a proven security bound.

## Local authentication envelope

The existing S5.D-2 MAC-protected parity frame receives an additional
session/profile/sequence/transcript-digest-bound HMAC-SHA256 relay envelope.
The relay refuses query 4801 and replayed/out-of-order sequence numbers.
Its root is assumed externally provisioned. This is a **single-process local
model**: it is NOT the pre-existing S3.C static schedule, NOT an independently
operated Alice/Bob service, and does not establish a multi-frame HMAC bound.
The S3.D outer-frame limit (1024) is NOT expanded or bypassed.

## S5.D and S5.E open requirements

1. Replace the local dual-parity frame with actual two-party public messages,
   and integrate a bounded streaming schedule with S3.C/S3.D or an equivalent
   audited authenticated-channel construction.
2. Bound the entire interactive public transcript including query selection,
   abort, confirmation and adaptive message lengths as a channel in the proof.
3. Establish general-adversary TLGR applicability, including cap coupling and
   random accepted matched-Z population.
4. Prove/justify total quantum and computational authentication advantage for
   a frozen profile and independently review the combined reduction.

**Security flags remain false.** Passing tests proves functional properties
of this research implementation, not conditional QKD security.

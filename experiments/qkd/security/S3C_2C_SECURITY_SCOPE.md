# S3.C-2c: authenticated privacy-amplification parameter exchange

**Status: unqualified simulation.** S3.C-2c extends the global S3.C transcript
through an Alice PA proposal, Bob acknowledgement, and Alice final commit.
The proposed Toeplitz seed is public and sampled with `secrets` after
reconciliation. The message authenticates its canonical bytes alongside the
raw-key bit count, output bit count, epsilon-PA representation, QST profile,
finite-key decision, and previous transcript digest. Bob's receiver checks the
parameters against its local state before acknowledging. No key is released.

**Important distinction:** The strict session still has **no verified quantum
conditional min-entropy**. Its PA exchange is a *diagnostic proposal only*;
it does NOT run a qualified extractor, certify the public seed's independence
from all adversarial quantum side information, or confer PSK-export rights.
The finite-key decision remains REJECT. The public report includes only a seed
hash and lengths. The seed itself is conveyed within the authenticated public
transcript, never treated as secret.

The earlier S3.C-2b `h2-ec-v1` schedule is retained as a compatibility path;
the strict path uses `h2-ec-pa-v1`. Each phase uses the same two independent
Alice/Bob transcript objects. A mutation, out-of-order stage, cross-session
message, or digest mismatch aborts. Session ID burning continues to be
crash-persistent only within the S3.B single-host registry assumptions.

**No security qualification:** source/device assumptions, theorem conformance,
composable MAC failure accounting, certified entropy, secure provisioning,
independent security review, real-QKD hardware claims, and QKD-derived HPKE
export are OUT OF SCOPE. `security_model_validated`, `security_qualified`, and
`hpke_export_authorized` remain false.

Acceptance evidence: `test_s3c2c_pa_integration.py`, all existing S3.C and
S3.B suites, S2.A2/S2.A3 regressions, and full CI. Do not claim completion
before executing the tests on EdgeExpert and documenting commit SHA/results.

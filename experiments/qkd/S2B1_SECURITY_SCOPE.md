# S2.B1 finite-key theorem-conformance audit

This source-level checker records unresolved proof obligations for experimental BB84 distillation. Its numerical Equation (2) evaluation is **diagnostic only**. Even a positive candidate length does **not** establish conditional min-entropy, secrecy, correctness, theorem equivalence, authentication provisioning or authorized HPKE key export.

The module validates expected source markers and records SHA-256 fingerprints. Source markers are not formal proofs. The exact theorem protocol, quota overshoot, optional oversampling, cap-abort semantics and quantum adversary assumptions require independent proof review. The paper's basis and device assumptions must be checked against the implementation and its threat model.

The finite-key code currently accepts an externally supplied pre-leak entropy number and evidence-ID string; neither is an independently verified evidence mechanism. M2.A supplies hypothetical demo evidence only and does not export keys. Do not change the security flags based on this audit.

No research bibliography or related-work ledger is stored in the repository.

Equation (2) already includes the correctness verification penalty through epsilon_cor. For numerical diagnosis, the syndrome disclosure enters leak_EC; the separately reported universal-hash confirmation tag is **not subtracted again**, avoiding double counting. This accounting convention requires independent proof-level reconciliation before any certification.

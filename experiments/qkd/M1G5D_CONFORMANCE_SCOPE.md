# M1.G5.D — Fail-closed BB84 security-model conformance audit

Reference: Tomamichel, Lim, Gisin and Renner, *Tight finite-key analysis for quantum cryptography*, Nature Communications 3, 634 (2012), DOI: 10.1038/ncomms1631 (Box 1 and Eq. 2).

## Scope

The audit enumerates theorem assumptions, implementation evidence, and blockers. Source-presence checks are indicators only: they do not establish correctness, theorem conformance, or cryptographic security. Previous independent functional tests remain separate evidence.

The actual experimental code uses publicly reproducible randomness, does not validate independent MAC-key provisioning, and lacks a theorem-aligned end-to-end reconciliation, correctness-verification and privacy-amplification security proof. The error-estimation sample is quota-ordered, not independently sampled from the theorem's prescribed population. The finite-key calculator produces numerical candidates only.

## Decision

Always `BLOCKED_SECURITY_MODEL_NOT_VALIDATED` in this stage. This is a successful *audit*, not a successful security validation. Do not set `SECURITY_MODEL_VALIDATED=true`, qualify keys, or allow QKD-derived HPKE export. A later milestone must substantively close and independently review each blocking requirement before changing that decision.

## Assumption guidance

Do not conflate an ideal authenticated channel in a formal proof with HMAC-key provisioning in an experimental implementation. Do not conflate reproducibility with private randomness. Do not count public parameter-estimation disclosures as if they were private key bits, and do not omit actual key-basis leakage. Review the exact proof's basis sample-selection and correctness-hashing conditions against implementation behavior before interpreting Equation (2).

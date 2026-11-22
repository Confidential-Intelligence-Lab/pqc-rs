# M1.H4.A — Independent classical quota-stopping model

This module is a mathematical reference for the idealized, **lossless** basis-choice process, not a cryptographic security proof. If Alice and Bob independently choose X with probability p_X, then a transmission yields X/X with probability p_X^2, Z/Z with probability (1-p_X)^2, and a basis mismatch with probability 2p_X(1-p_X). An exact finite-state dynamic program determines the first time both capped counts reach n_X and k_Z. `max_transmissions` is an **engineering abort cap**, not automatically a security theorem premise. The distribution reported by the model includes conditioning on this cap explicitly.

Uniform random sampling from a fixed eligible population of size N is represented by P(S)=1/binomial(N,n) for each size-n subset, independently of the underlying bits. This module tests the combinatorial reference, not an actual sampling implementation or proof of independence against Eve.

**Source:** Tomamichel, Lim, Gisin, Renner (2012), *Tight finite-key analysis for quantum cryptography*, Box 1, DOI 10.1038/ncomms1631. Box 1's acquisition quotas and uniform raw-key subset are considered. A complete theorem-level comparison, including detection/loss patterns, source characterization, authenticated communications, random choices, finite-key analysis and treatment of the transmission cap, is outstanding.

The oracle does **not** assert that the current H3.B implementation follows this distribution. It assumes independent basis choices and full detection and has no integration with source bits, measurement data, or HPKE. Outputs always retain `theorem_sampling_validated=false`, `security_model_validated=false`, `hpke_export_authorized=false`.

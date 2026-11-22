# S5.B-S: Standards-referenced QKD research-security disposition

**Research baseline:** `94d687501797858ccf2ca0038e3da37df6f10378` (`research/qkd-security-qst1`).
**Interpretation:** A standards-referenced *research method and evidence map*, **not** a third-party certification, not conformance to a hardware protection profile, and not a quantum-security theorem.
**Version:** 0.1 / 2026-11-21.

## Decision

Use the published ETSI GS QKD 005 V1.1.1 scientific-security-proof and implementation-verification separation as the primary *research methodology*. Use ETSI GS QKD 016 V2.1.1, especially FCS_QKD.1, as a **requirements comparison**, not as a claim that a simulated protocol is a conforming or certified Target of Evaluation. ISO/IEC 23837-1/-2:2023 concerns QKD module evaluation and optical components, and is not directly satisfied by CUDA-Q simulation. ITU-T X.1710 concerns network security and belongs mainly to S6; ITU-T X.1711 (2026-03) provides an additional protocol-architecture reference. Avoid relying on the in-progress ETSI QKD 005 revision as if published.

**Decision now:** research-model engineering correspondence and reproducible measurement evidence are documented; formal theorem-supported conditional security is **NOT established**. The implementation continues to deny simulated-key export. Mapping standard sections to code is not proof of their satisfaction.

## Published reference set and what can be claimed

| Reference | Applicable provision or scope | pqc-rs evidence | Research assessment |
|---|---|---|---|
| ETSI GS QKD 005 V1.1.1 (2010), Sec. 4.3, 4.4, 4.7 | Scientific security proof + implementation correspondence; source/receiver model; authenticated classical postprocessing | S4.A-G, S3.C-D, S5.A-B | Methodology adopted; scientific proof applicability open |
| ETSI GS QKD 016 V2.1.1 (2024), FCS_QKD.1.1 | QKD protocol must have a matching composed proof bounding its security parameter | TLGR candidate Eq. (2), S4.C-D, S5.B | **NOT satisfied** as a security-proof claim |
| ETSI GS QKD 016 V2.1.1, FCS_QKD.1.2 | Per-execution requirements and repetition/attempt tracking | S3.B/S3.D one-host reservation | Partial engineering analogy; no module conformity |
| ISO/IEC 23837-1:2023 | Baseline security functional requirements for actual QKD modules, optical and classical components | S4 model and negative interface tests | Hardware/module scope inapplicable to simulation |
| ISO/IEC 23837-2:2023 | Evaluation/test methods for actual QKD modules | S4.G testing only | Cannot claim ISO evaluation without full applicable assessment |
| ITU-T X.1711 (2026) | Quantum-layer QKD protocol architecture | S4 protocol sequence | Informative architecture comparison |
| ITU-T X.1710 (2020) | QKD network threat/security framework | S3/S6 interfaces | Deferred to S6; no network conformance |

## Research disposition policy

1. `RESEARCH_IMPLEMENTATION_VALIDATED` is a *human-reviewed* Gate A research decision, supported by source revision, reproducibility, negative tests and protocol/model disclosures. A document inventory alone never auto-approves it.
2. `RESEARCH_PROFILE_ALIGNED` can mean **documented methodological alignment** after human review; it must not mean ETSI/ISO certification or conformity to FCS_QKD.1's proof requirement.
3. `CONDITIONAL_SECURITY_SUPPORTED` requires a published or independently reviewed theorem whose exact hypotheses match the implemented *accepted branch* and derive positive valid secrecy and correctness bounds under declared assumptions. The selection of a published paper or formula alone is insufficient.
4. `PRODUCTION_EXPORT_AUTHORIZED` is not a consequence of any of the above and remains false for simulated provenance.

## Exact open theorem/application issues

- **Hard cap:** show the capped *accepted* trace is a public, causally equivalent abort filtering of the reference protocol for general quantum Eve, not just for classical recorded first-hit sequences.
- **Variable Z samples:** `m1h2_authenticated_sampling.py` passes `actual_z_test_size` to `BoundInput`. Precommitted `k_test` is a minimum, and `k_actual >= k_min`. A mathematically valid variable-sample theorem or conservative bound must justify the substitution. No automatic positive entropy credit from observed `k_actual`.
- **TLGR supplementary hypotheses:** review the full cited proof and verify source preparation, receiver detection assumptions, randomness independence, public transcript, stopping, smoothing and adversarial class.
- **Correctness and leakage:** reconcile Eq. (2)'s correctness penalty with the implemented confirmation tag; do not double charge the tag in the theorem-shaped bound. Include syndrome leakage and public postprocessing.
- **Authentication:** S3.D counts only outer frames, not all inner MACs or derivation-security reductions. Require a separate computational multi-message bound for HMAC-SHA256 and key schedule.
- **Privacy amplification:** verify Toeplitz two-universality, quantum side-information independence of public seed, smoothing conventions and actual output length.

These issues can be discharged by reusing a proven published protocol theorem and theorem-matched implementation, rather than publishing an original QKD proof. Any code adaptation must trigger a new source-mapping and test review.

## Evidence and approval gates

| Gate | Evidence required | Current disposition |
|---|---|---|
| A: functional research prototype | Frozen revision; full QKD suite; real CUDA-Q eight-case/attack experiment; key-export denial; independent source review | Ready for **human approval review**, not self-certified |
| B: theorem-supported conditional research security | Frozen theorem profile; complete applicability matrix; accepted-branch bound; finite-key candidate justified; computational auth composition; independent research review | **OPEN** |
| C: production/physical module certification | Evaluated hardware/module, source assurance, deployment/storage/operational certification and authorized provider boundary | Out of QST-1 scope |

## Source/reference links

- ETSI GS QKD 005 V1.1.1: https://www.etsi.org/deliver/etsi_gs/QKD/001_099/005/01.01.01_60/gs_QKD005v010101p.pdf
- ETSI GS QKD 016 V2.1.1: https://www.etsi.org/deliver/etsi_gs/QKD/001_099/016/02.01.01_60/gs_QKD016v020101p.pdf
- ETSI QKD 005 revision work item (draft status): https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=58005
- ISO/IEC 23837-1:2023: https://www.iso.org/standard/77097.html
- ISO/IEC 23837-2:2023: https://www.iso.org/standard/77309.html
- ITU-T X.1711 (2026-03): https://www.itu.int/itu-t/recommendations/rec.aspx?rec=16739
- ITU-T X.1710 (2020): https://www.itu.int/ITU-T/recommendations/rec.aspx?rec=14452

**Required denial flags:** `security_model_validated=false`, `security_qualified=false`, `hpke_export_authorized=false`, `qkd_psk_available=false`.

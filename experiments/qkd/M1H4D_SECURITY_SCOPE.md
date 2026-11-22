# M1.H4.D: Complete matched-Z parameter estimation

The authenticated BB84 experimental pipeline now discloses **all** eligible matched-Z observations after quota acquisition, including Z overshoot before X-quota completion. Alice and Bob independently check the complete, ordered Z index list, all disclosed bits, error count, and actual Z sample size. The numerical finite-key calculation consumes the actual Z count rather than the configured minimum quota. Raw X-key values remain undisclosed.

The previous M1.H4.C audit recorded the historical Z-subsampling discrepancy; its source guards intentionally reject subsequent implementation revisions and must not be interpreted as a current conformance result. H4.D regression tests explicitly exercise the former `ZZX` counterexample.

**Unresolved:** H3.B oversampling, quota-based/cap-conditioned stopping-model equivalence, independence and authentication provisioning, physical source assumptions, finite-key theorem hypotheses, and end-to-end secrecy. CUDA-Q simulation is not physical QKD. No security qualification or HPKE key export is authorized. Research bibliography is intentionally not in this repository.

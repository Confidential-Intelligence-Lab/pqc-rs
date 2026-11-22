# M1.H4.F — Exact classical quota-overshoot and cap conditioning model

This additive, independent reference module computes a finite-cap **rational** joint distribution of stopping time T and unsaturated matched basis populations (X_T,Z_T). It assumes independent ideal basis draws with P(XX)=p_x^2, P(ZZ)=(1-p_x)^2, P(mismatch)=2p_x(1-p_x). Success is the **first** time X_T >= n_x and Z_T >= k_z; a transmission cap causes abort otherwise.

A separate brute-force path enumerator validates small cases. The dynamic program records both the completed joint distribution and cap-abort mass, with conditional overshoot probabilities normalized **only over successful completions**. At first passage, no more than one basis population can exceed its quota. It models counts before quota saturation: accepted quota counters alone cannot represent this distinction.

Uniform index selection conditional on an *eligible preselection population* is a separate combinatorial statement, not uniformity after the selected indices have been announced in the authenticated transcript. The module does not attempt to prove conditional independence from Eve, quantum source assumptions, authentication-key provisioning, reconciliation leakage, finite-key theorem applicability, or composable security. Cap-conditioned probabilities are not themselves a finite-key secrecy proof.

The module and its tests contain no bibliography/related-work ledger. No private source bits, quantum keys, session secrets, or HPKE material are exported. All qualification flags remain false. The H4.E audit and prior implementation files are unchanged.

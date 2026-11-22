# G5.C2: Authenticated parameter-estimation integration

This experimental component uses actual CUDA-Q measurement records, the existing
G5.B authenticated public transcript, and the G3 numerical finite-key equation.
It does **not** authorize key generation, key export, or security qualification.

- The sender's and receiver's basis announcements are authenticated.
- X-basis positions are selected under the *quota policy*, then both parties
  publish their X test bits through separately authenticated, transcript-bound
  public frames. Both peers can check the resulting error count independently.
- No Z-basis measurement bits are sent in these public frames. The X bits are
  completely disclosed and must not be treated as secret key material.
- The selected positions are quota-ordered rather than a fresh uniform sample.
  This is **not a proof of conformance** to the exact Tomamichel et al. (2012)
  parameter-estimation/sampling protocol.
- Q_tolerance is a configured threshold, distinct from the measured X QBER.
  A threshold failure aborts, and an accepted result is still *unqualified*.
- The G3 bound receives n, k, and a configured threshold. Its leakage input is
  caller-supplied: there is no actual Z-key reconciliation in this module.
- Independently provisioned MAC keys and secret quantum source randomness are
  **not validated**. A public deterministic simulator seed is not secret.
- The simulator is centralized for experiments. Distinct record types do not
  establish physical or process-level separation of Alice and Bob.
- Neither an authenticated transcript nor a positive numerical bound by itself
  establishes composable QKD security or secure HPKE use.

The next milestone must reconcile exact theorem sampling/quota rules, leakage,
correctness, authentication failure probabilities, and source/device assumptions.
References and literature notes are intentionally maintained in ChatGPT only.

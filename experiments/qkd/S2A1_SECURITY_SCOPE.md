# S2.A1 experimental universal-hash confirmation

- Implements independent-seed binary Toeplitz confirmation, authenticated using locally shared simulation HMAC-SHA256 key material.
- The collision bound for any two *fixed, distinct* bitstrings is `2^-t` over an independent uniform Toeplitz seed of length `n+t-1`. It is an upper bound on undetected mismatch only if the mismatched strings cannot be adaptively chosen after the seed is known.
- The seed is public and does not count as raw-key leakage **under the stated independence assumption**; the transmitted `t`-bit tag is conservatively counted as `t` disclosure bits. Authentication overhead and key-consumption assumptions remain unqualified.
- The local simulator is not a distributed authentication protocol. Distinct parties need independent authenticated state and verified session, sequence, and key provisioning. Adversarial/replay protection here is incomplete.
- The module **does not** replace M1.E1's correction algorithm and **does not** alter M2.A's finite-key decision. Both retain their prior security restrictions.
- A comparison/hash collision test cannot establish quantum secrecy or source min-entropy. No QKD key export or HPKE authorization is permitted.
- Follow-up S2.A2: select and analyze a concrete syndrome decoding strategy; S2.A3: wire confirmed tags and leakage into finite-key accounting and retire the insecure SHA-256 confirmation path.

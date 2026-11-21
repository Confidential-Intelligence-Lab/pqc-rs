# S2.B2 Strict Quota-Stop Reference — Security Scope

This experiment checks the **observable prefix** of the acquisition records:
acquire until both matched-X key quota and matched-Z testing quota are met,
then stop at the first such transmission. The complete eligible-Z set at that
first-hit time is disclosed; n key bits are randomly selected from eligible-X.
The existing H2/M2.A mechanisms conduct those latter operations.

A fixed-transmission *cap* is a resource abort only, never evidence of a
fixed-window security proof. If the input includes records past the first hit,
the strict path rejects. Partial sequences that never meet quotas abort.

No assumption is made that a supplied record batch proves when the external
source stopped. In particular an attacker can prefilter, reorder, fabricate,
or suppress input events; this module cannot observe that. Basis RNG, source
independence, quantum side information, loss/detection, authenticated-channel
key provisioning, and composable finite-key secrecy remain unverified.

S2.B2 neither issues an entropy certificate nor permits HPKE PSK export.
The numerical Equation (2) is diagnostic. The conditional 2^-40 confirmation
collision bound does not establish secret-key indistinguishability. All
simulated results remain unqualified and non-exportable.

The reference reconciliation mechanism remains bounded-distance; H2 and M2.A
still generate authentication keys internally. Unqualified simulation
fingerprints are not production authorization credentials.

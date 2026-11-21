# G5.C1: Real measurement records -> authenticated classical sifting

This additive experimental module records Alice's preparation bits/bases and
Bob's measurement bits/bases separately, authenticates the actual basis arrays
produced by the simulation with the existing G5.B public discussion, and checks
that both peer views lead to identical accepted Z and X positions under G5.A
quotas. If the transmission cap is reached before quotas, it authenticates an
abort. It stops after the authenticated quota/abort announcement: the X-basis
parameter-estimation disclosure and the final six-message protocol remain for
G5.C2.

The local simulation orchestrator necessarily controls both peers and the
quantum channel. It does not constitute a distributed two-machine protocol or
prove absence of cross-party data access. The only public payloads are basis
arrays, quota counts and abort status; no raw preparation or measurement bits
are intentionally transmitted. Authentication keys and session IDs come from
os.urandom by default and are independently provisioned *only within this local
experiment*. Real-world key provisioning, random-source assurance, detection
models, theorem-specific sampling and composable authentication budget remain
outside scope.

The existing G5.B transport is a sequential, fixed-schema state machine. This
integration does not modify it, and does not finalize the transcript. Per-basis
error statistics are intentionally not computed or authenticated in G5.C1.
Publicly reproducible simulation seeds are not secret source randomness.

All outputs remain `security_model_validated=false`,
`security_qualified=false`, and `hpke_export_authorized=false`.

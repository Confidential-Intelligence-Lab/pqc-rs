# IETF review announcement drafts

> **Coordination copy.** Replace every `{{PLACEHOLDER}}` from the frozen
> reviewer packet before posting. Send the two messages separately because
> they ask different communities for different feedback. Use plain text and do
> not attach archives to the mailing-list messages.

The PQUIP list is `pqc@ietf.org`; its archive and subscription information are
available from the [PQUIP working-group page](https://datatracker.ietf.org/wg/pquip/about/).
The HPKE list is `hpke@ietf.org`; its archive and subscription information are
available from the [HPKE working-group page](https://datatracker.ietf.org/wg/hpke/about/).

## PQUIP announcement

**To:** `pqc@ietf.org`

**Subject:** External review: PQC-rs v0.4.0 release candidate

```text
Hello PQUIP,

I am inviting review of the fixed v0.4.0 release candidate for PQC-rs, a standards-driven Rust ecosystem for post-quantum key establishment and HPKE.

The candidate covers FIPS 203 ML-KEM-512/768/1024 and RFC 9180 Base/PSK HPKE, including experimental pure-PQ and PQ/traditional profiles pinned to draft-ietf-hpke-pq-05. It includes standards traceability, malformed-input tests, cross-provider interoperability, explicit secret handling, fuzzing, generated-code and timing screens, SBOMs, and signed assurance evidence.

PQC-rs uses RFC 9958 as Informational engineering and migration guidance; it does not claim to “implement RFC 9958.” I would especially welcome PQUIP feedback on whether the project reflects that guidance responsibly: cryptographic agility, protocol and infrastructure impact, migration risk, interoperability, and the boundaries of its claims.

The review target is fixed at:

  tag:    {{REVIEW_TAG}}
  commit: {{REVIEW_COMMIT}}
  closes: {{REVIEW_END_DATE_AND_TIME_UTC}}

Reviewer packet: {{REVIEW_PACKET_URL}}
Release and evidence: {{RELEASE_URL}}
Non-sensitive implementation feedback: {{REVIEW_ISSUE_URL}}

Discussion on this list is welcome. For tracking, I would appreciate actionable implementation findings also being recorded in GitHub. Please use the private vulnerability-reporting channel identified in the reviewer packet for sensitive findings.

Thank you,

Ro Cammarota
Associate Professor of Computer Science, UC Irvine
Confidential Intelligence Lab
```

## HPKE announcement

**To:** `hpke@ietf.org`

**Subject:** Implementation review: PQC-rs HPKE and draft-ietf-hpke-pq-05

```text
Hello HPKE,

I am inviting implementation and interoperability review of the HPKE portion of the fixed PQC-rs v0.4.0 release candidate.

The Rust crate implements RFC 9180 Base and PSK modes with ML-KEM and supports the pure-PQ KEMs ML-KEM-512/768/1024 and the hybrid combinations ML-KEM-768+X25519, ML-KEM-768+P-256, and ML-KEM-1024+P-384. The PQ and hybrid profiles are explicitly pinned to draft-ietf-hpke-pq-05 and remain experimental.

I would particularly value review of:

* RFC 9180 Base/PSK setup, key schedule, context, and exporter behavior;
* suite and KEM identifiers, serialization, and labeled derivation behavior;
* PSK input validation and negative cases;
* pure-PQ and hybrid KEM composition and component ordering under -05; and
* transcript or cross-provider mismatches not covered by the current tests.

The review target is fixed at:

  tag:    {{REVIEW_TAG}}
  commit: {{REVIEW_COMMIT}}
  closes: {{REVIEW_END_DATE_AND_TIME_UTC}}

Reviewer packet: {{REVIEW_PACKET_URL}}
Release and evidence: {{RELEASE_URL}}
Non-sensitive implementation feedback: {{REVIEW_ISSUE_URL}}

Discussion on this list is welcome. For tracking, I would appreciate actionable implementation findings also being recorded in GitHub. Please use the private vulnerability-reporting channel identified in the reviewer packet for sensitive findings.

Thank you,

Ro Cammarota
Associate Professor of Computer Science, UC Irvine
Confidential Intelligence Lab
```

## Posting checklist

- [ ] Confirm the candidate tag and commit from an anonymous clone.
- [ ] Confirm the reviewer packet and all evidence links are public.
- [ ] Confirm the review issue and private security channel work.
- [ ] Confirm the sender is subscribed or account for moderation delay.
- [ ] Use the same closing timestamp in both messages and the packet.
- [ ] Archive the final sent text and message URLs in the disposition record.
- [ ] Reply in-thread only for material updates; do not send routine reminders
      to the full lists.

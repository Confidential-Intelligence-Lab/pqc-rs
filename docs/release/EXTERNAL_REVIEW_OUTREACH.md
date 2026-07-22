# External review outreach templates

> **Coordination copy.** Replace all `{{PLACEHOLDER}}` fields from the frozen
> reviewer packet before sending. Keep each invitation focused; do not imply
> that a recipient endorses the project merely by reviewing it.

## Review audience

RFC 9958 lists Aritra Banerjee, Tirumaleswar Reddy.K, Dimitrios
Schoinianakis, Tim Hollebeek, and Mike Ounsworth as authors. Each should receive
an individual message rather than a group mailing.

Selected colleagues should be invited according to a specific area of
expertise. Useful review lanes include:

- FIPS 203 correctness and malformed-input behavior;
- RFC 9180 and post-quantum HPKE interoperability;
- Rust API design, feature boundaries, and secret ownership;
- side-channel methodology, generated code, and zeroization;
- release assurance and reproducibility; and
- migration guidance and deployment usability.

## Personal invitation to an RFC 9958 author

**Subject:** Invitation to review the PQC-rs v0.4.0 release candidate

```text
Dear {{NAME}},

I am preparing the stable v0.4.0 release of PQC-rs, a standards-driven Rust ecosystem for post-quantum key establishment and HPKE. I have opened a 21-day public review of a fixed release candidate and would be grateful for your perspective as a co-author of RFC 9958.

The release covers FIPS 203 ML-KEM-512/768/1024 and RFC 9180 Base/PSK HPKE, including experimental PQ and PQ/traditional profiles pinned to draft-ietf-hpke-pq-05. The project uses RFC 9958 as engineering and migration guidance; it does not present itself as an “RFC 9958 implementation.”

I would especially value your view on whether the project translates that guidance responsibly: cryptographic agility, protocol and infrastructure impact, interoperability, migration risk, and the boundaries of its claims. There is no expectation of a comprehensive code audit; even comments on framing, omissions, or misleading assumptions would be extremely useful.

Candidate and reviewer packet: {{REVIEW_PACKET_URL}}
Review closes: {{REVIEW_END_DATE_AND_TIME_UTC}}

Non-sensitive feedback can be added at {{REVIEW_ISSUE_URL}}. Sensitive findings should use the private channel identified in the packet.

Thank you for considering it.

Best,
Ro
```

## Personal invitation to a colleague

**Subject:** Focused review request: PQC-rs v0.4.0 candidate

```text
Hi {{NAME}},

I am opening a 21-day public review of the fixed PQC-rs v0.4.0 release candidate. This release covers FIPS 203 ML-KEM and RFC 9180 Base/PSK HPKE, with explicit secret handling, interoperability tests, and reproducible assurance evidence.

Given your work on {{EXPERTISE}}, I would particularly value a focused look at {{SPECIFIC_REVIEW_REQUEST}}. There is no expectation that you review the whole repository; a narrow technical observation, failed integration, API concern, or documentation gap would be genuinely helpful.

Candidate and reviewer packet: {{REVIEW_PACKET_URL}}
Review closes: {{REVIEW_END_DATE_AND_TIME_UTC}}

Non-sensitive feedback can be added at {{REVIEW_ISSUE_URL}}. The packet also identifies a private channel for sensitive findings.

Many thanks,
Ro
```

## Suggested personalization lines

Use one precise sentence rather than sending a generic request:

- “I would value your assessment of the FIPS 203 boundary, especially key
  checks, implicit rejection, and malformed-input behavior.”
- “I would value your assessment of the RFC 9180 transcript behavior and the
  revision-pinned `draft-ietf-hpke-pq-05` profiles.”
- “I would value your assessment of the public Rust API, including ownership,
  error semantics, feature flags, and accidental secret copying.”
- “I would value your assessment of the timing and generated-code methodology,
  particularly what the evidence does and does not justify.”
- “I would value your assessment of whether the documentation gives an
  integrator a realistic picture of migration effort and operational risk.”
- “I would value your assessment of the release evidence, reproducibility, and
  whether any assurance claim is stronger than the artifacts support.”

## Day-10 reminder

**Subject:** Reminder: PQC-rs review closes {{REVIEW_END_DATE}}

```text
Hi {{NAME}},

A brief reminder that the PQC-rs v0.4.0 candidate review closes on {{REVIEW_END_DATE_AND_TIME_UTC}}. If you have had a chance to look at {{SPECIFIC_REVIEW_REQUEST}}, even a short observation would be valuable. No response is expected if your schedule does not permit it.

Reviewer packet: {{REVIEW_PACKET_URL}}

Best,
Ro
```

## Thank-you and disposition note

```text
Hi {{NAME}},

Thank you for reviewing the PQC-rs candidate. I recorded your feedback as {{DISPOSITION}} and tracked it at {{DISPOSITION_URL}}. {{ONE_SENTENCE_OUTCOME}}

I appreciate the time and care you put into it.

Best,
Ro
```

## Outreach log

Track outreach privately; do not commit personal email addresses or private
comments to the public repository.

| Reviewer | Area requested | Sent | Reminder | Response | Public disposition |
|---|---|---|---|---|---|
| {{NAME}} | {{AREA}} | {{DATE}} | {{DATE_OR_NA}} | {{STATUS}} | {{URL_OR_PENDING}} |

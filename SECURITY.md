# Security Policy

## Project status

PQC-rs is pre-release software and has not completed an independent security audit or formal validation. Current releases are intended for research, evaluation, interoperability work, and controlled testing.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue, discussion, or pull request.

Use GitHub's private vulnerability-reporting or security-advisory mechanism for the repository. Include:

- the affected package and revision;
- a concise impact assessment;
- reproduction steps or a proof of concept;
- whether secret material, correctness, interoperability, or availability is affected;
- any proposed remediation.

If private reporting is unavailable, contact the maintainers through a private channel listed on the repository owner's GitHub profile and request a secure disclosure channel. Do not send sensitive exploit details until that channel is established.

## Response expectations

Maintainers will acknowledge a credible report, assess scope and severity, coordinate remediation, and publish an advisory when appropriate. Timelines depend on technical complexity and downstream coordination; no fixed remediation deadline is promised.

## Supported versions

Until the first stable release, only the latest revision of the default branch and the latest published pre-release are considered for security fixes. A formal supported-version table will be introduced before version 1.0.

## Security claims

Testing, side-channel measurements, compiler audits, SBOMs, and release evidence are engineering controls. They are not substitutes for independent audit, FIPS validation, Common Criteria certification, or application-specific threat analysis.

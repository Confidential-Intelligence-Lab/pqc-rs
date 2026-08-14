# PQC-Forge Secure-Channel Evaluation

## 1. Purpose

This document defines the experimental contract for evaluating the
PQC-Forge negotiated secure-channel path.

The evaluation measures both the cost of establishing and using negotiated
post-quantum secure channels and the extent to which cryptographic capability
changes remain localized behind explicit protocol, resolution, binding, and
activation boundaries.

Measurement semantics are fixed here before benchmark instrumentation and
result collection are introduced.

## 2. Evaluation Baseline

The secure-channel evaluation begins from merged `main` revision:

~~~text
dabef00080af93349bf837d7fec3f7f99f811230
~~~

Evaluation development is performed on:

~~~text
feature/secure-channel-evaluation
~~~

Paper-facing methodology and raw experimental results belong under:

~~~text
paper/evaluation/
~~~

Secure-channel Criterion benchmarks belong under:

~~~text
crates/pqc-secure-channel/benches/
~~~

Existing direct HPKE benchmarks are lower-layer comparison baselines. They
must not be reported as negotiated secure-channel measurements.

## 3. Evaluated Cryptographic Profiles

The evaluation uses the authoritative secure-channel capability registry and
closed HPKE profile resolution already present in the implementation.

The evaluated profiles are:

| Capability ID | Construction | KDF | AEAD |
| --- | --- | --- | --- |
| `0x0101` | ML-KEM-768 | HKDF-SHA256 | AES-256-GCM |
| `0x0102` | ML-KEM-1024 | HKDF-SHA384 | AES-256-GCM |
| `0x0111` | ML-KEM-768 + X25519 | HKDF-SHA256 | AES-256-GCM |

Peers negotiate complete capability identifiers. The evaluation does not
model independent negotiation of arbitrary KEM, KDF, and AEAD components.

All evaluated profiles must traverse the same upper protocol and
secure-channel workflow.

## 4. Evaluation Workflow

The reference workflow is:

~~~text
capability advertisement
        |
        v
capability negotiation
        |
        v
protocol establishment
        |
        v
EstablishedProtocolContext
        |
        v
closed HPKE profile resolution
        |
        v
canonical secure-channel binding
        |
        v
sender / receiver activation
        |
        v
protected data exchange
~~~

The evaluation must exercise public or architecturally representative
interfaces. Benchmark code must not reproduce cryptographic implementation
logic or bypass architectural boundaries merely to simplify timing.

## 5. Measurement Principles

The following rules apply to all accepted measurements.

1. Correctness is established before performance data for a configuration are
   accepted.
2. All cryptographic profiles traverse the same benchmark workflow.
3. Microbenchmarks and end-to-end benchmarks remain distinct.
4. Recipient key generation is outside activation timing unless key generation
   is itself the benchmarked operation.
5. Existing cryptographic material required to enter a measured region is
   prepared outside that region.
6. Benchmark code does not bypass negotiation, profile resolution, binding, or
   activation when those stages are part of the claimed measurement.
7. Raw results are retained.
8. The Git revision, execution environment, benchmark configuration, and
   relevant toolchain information are recorded with accepted results.
9. Outliers are not silently removed.
10. Independently measured component timings are not assumed to sum exactly to
    independently measured end-to-end timings.

## 6. Measurement Boundaries

### 6.1 Capability Negotiation

This measurement captures protocol work required to select a mutually
supported secure-channel capability according to the protocol's selection
rules.

The timed region includes capability comparison and selection logic required
by the established protocol implementation, together with any policy filtering
actually exercised by the reference workflow.

The timed region excludes:

- recipient key generation;
- HPKE encapsulation or decapsulation;
- HPKE key scheduling;
- secure-channel binding construction;
- protected-message operations.

The output is the negotiated capability evidence required by subsequent
protocol establishment.

### 6.2 Profile Resolution

This measurement captures conversion of validated negotiated capability
evidence into the closed secure-channel profile represented by
`ResolvedHpkeProfile`.

The timed region begins with an already validated negotiated capability and
ends when profile resolution returns.

It excludes:

- capability negotiation;
- secure-channel binding;
- HPKE setup;
- protected-message operations.

This measurement approximates the direct runtime cost of the
crypto-agility indirection layer.

### 6.3 Secure-Channel Binding

This measurement captures construction of the canonical
`SecureChannelBinding` from an already established protocol context and the
required application context.

The timed region includes the canonical binding construction performed by the
secure-channel integration layer.

It excludes:

- capability negotiation;
- profile resolution;
- HPKE setup;
- protected-message operations.

### 6.4 Sender Activation

Sender activation begins with:

- an `EstablishedProtocolContext`;
- existing recipient public key material;
- the required application context.

The timed region includes:

1. closed profile resolution;
2. canonical secure-channel binding construction;
3. HPKE encapsulation;
4. HPKE key schedule execution;
5. sender-context creation.

The timed region excludes recipient key generation.

The output is an activated sender context together with the encapsulated
material required by the receiver.

### 6.5 Receiver Activation

Receiver activation begins with:

- an `EstablishedProtocolContext`;
- existing recipient private key material;
- an existing encapsulated key produced by the corresponding sender setup;
- the required application context.

The timed region includes:

1. closed profile resolution;
2. canonical secure-channel binding construction;
3. HPKE decapsulation;
4. HPKE key schedule execution;
5. receiver-context creation.

The timed region excludes recipient key generation and sender activation.

### 6.6 Protected Data

Protected-data measurements begin after sender and receiver activation have
completed.

The initial payload size is:

~~~text
1024 bytes
~~~

This preserves comparability with the existing lower-level HPKE `seal_1k`
benchmark while keeping the negotiated secure-channel measurement distinct
from that lower-layer baseline.

Separate measurements are collected for:

- `seal`;
- `open`.

Activation is outside these timed regions.

Additional payload sizes may be introduced later, but the 1024-byte case is
the initial required comparison point.

### 6.7 End-to-End Establishment

End-to-end establishment is measured independently from the component
microbenchmarks.

The measured workflow includes the complete negotiated secure-channel path
required to move from capability inputs through established protocol context,
profile resolution, binding, and sender/receiver activation to a usable
secure channel.

The precise fixture inputs for this benchmark must be frozen before result
collection.

The end-to-end result is measured directly. It must not be reconstructed by
summing independently collected microbenchmark results.

## 7. Correctness Requirements

A benchmark configuration is considered valid only if its corresponding
reference workflow succeeds functionally before timing data are accepted.

At minimum, each supported profile must demonstrate:

1. successful capability negotiation;
2. successful protocol establishment;
3. resolution to the intended closed HPKE profile;
4. sender activation;
5. receiver activation;
6. successful protected-message sealing;
7. successful protected-message opening;
8. recovered plaintext equal to the original plaintext.

Negative experiments are evaluated separately and are not mixed with
successful-path performance distributions.

## 8. Negative and Mismatch Experiments

The evaluation will include failure-path experiments for architectural
boundaries such as:

- unsupported capability identifiers;
- malformed or incompatible cryptographic material;
- mismatched established protocol contexts;
- mismatched secure-channel binding inputs;
- invalid or incompatible encapsulated material;
- other implementation-supported inconsistencies that should fail explicitly.

These experiments are primarily correctness and failure-localization evidence.
They are not automatically treated as performance benchmarks.

The accepted result for each case must identify the architectural boundary at
which rejection occurs.

## 9. Comparison With Lower-Level HPKE Baselines

Existing HPKE Criterion benchmarks measure direct cryptographic operations such
as sender setup, receiver setup, and 1 KiB sealing.

The secure-channel evaluation uses those measurements only as lower-layer
comparison baselines.

Where appropriate, results may compare:

~~~text
direct HPKE primitive cost
        versus
negotiated secure-channel activation cost
        versus
complete protocol establishment cost
~~~

Such comparisons are intended to characterize the incremental systems cost
associated with cryptographic agility, protocol binding, and negotiated
activation.

They must not imply that independently measured components form an exact
additive decomposition of end-to-end latency. An overhead value must not be
derived by subtracting independently measured lower-layer and higher-layer
benchmarks unless their fixtures, timed boundaries, and experimental
conditions make that subtraction valid.

## 10. Change-Localization Evaluation

A later evaluation stage will introduce a controlled cryptographic capability
change and record which architectural elements must change.

The experiment will distinguish changes required in areas such as:

- protocol capability registration;
- secure-channel profile resolution;
- cryptographic implementation or provider integration;
- protocol establishment;
- binding;
- activation;
- application workflow;
- tests and benchmark fixtures.

The objective is to quantify whether cryptographic evolution remains localized
behind the intended architectural boundaries rather than diffusing
algorithm-specific control flow through upper layers.

## 11. Transport and Execution Evaluation

Transport and fragmentation experiments are evaluated separately from the
initial in-memory reference workflow.

Where such experiments are performed, they must preserve the same protocol and
secure-channel semantics.

Transport-specific measurements must not be generalized beyond the transports
and execution behaviors actually exercised.

## 12. Result Recording and Reproducibility

Accepted paper-facing results must retain enough information to identify the
measurement context.

At minimum, record:

- Git revision;
- branch or release reference;
- Rust toolchain;
- target architecture;
- processor or system-on-chip model;
- operating system;
- relevant power or performance mode when controlled;
- benchmark harness and relevant configuration;
- evaluated capability/profile;
- measured operation;
- payload size where applicable;
- raw benchmark output.

Raw results should be retained under:

~~~text
paper/evaluation/raw/
~~~

A final reproducibility freeze will identify the exact revision and evidence
used to generate paper tables and figures.

## 13. Initial Evaluation Sequence

The evaluation proceeds in the following order:

~~~text
E1a  Freeze experimental contract
E1b  Freeze benchmark matrix and fixture architecture
E1c  Implement reference workflow
E1d  Add benchmark instrumentation
E1e  Validate correctness and benchmark isolation
E2   Execute negotiated crypto-agility matrix
E3   Compare pure-PQ and hybrid composition
E4   Execute negative and mismatch experiments
E5   Exercise a real transport
E6   Exercise fragmentation / partial-progress behavior
E7   Produce reproducible demonstration
E8   Collect performance results
E9   Perform change-localization experiment
E10  Reproducibility freeze
~~~

Performance result collection must not begin until the relevant benchmark
semantics and fixtures have been frozen and validated.

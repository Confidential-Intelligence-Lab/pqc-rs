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

## 14. E1b Benchmark Matrix and Fixture Contract

This section freezes the initial benchmark matrix and fixture architecture
before reference-workflow and Criterion implementation.

### 14.1 Profile Parameterization

All successful-path benchmarks are parameterized over the same three
registered secure-channel capabilities:

| Benchmark label | Capability |
| --- | --- |
| `MLKEM768` | `HPKE_ML_KEM_768` (`0x0101`) |
| `MLKEM1024` | `HPKE_ML_KEM_1024` (`0x0102`) |
| `MLKEM768-X25519` | `HPKE_ML_KEM_768_X25519` (`0x0111`) |

A common fixture representation supplies at least:

- benchmark label;
- capability identifier;
- recipient public key material;
- recipient private key material.

Algorithm-specific key-material construction is confined to fixture
preparation. Negotiation, establishment, resolution, binding, activation, and
protected-message benchmark workflows must not contain separate
profile-specific application paths.

### 14.2 Controlled Negotiation Fixture

Capability negotiation uses structurally equivalent three-capability inputs
for every target profile.

For target capability `T`, with the other registered capabilities denoted
`A` and `B`, the fixture has the form:

~~~text
local offer:  [T, A, B]
peer offer:   [A, T, B]
policy allow: [A, B, T]
~~~

All three lists contain exactly the three registered secure-channel
capabilities and contain no duplicates.

Local offer preference is authoritative, so the expected negotiated
capability is always `T`. The permutation is constructed consistently for all
profiles so that capability identity is not intentionally coupled to a
different negotiation-list size or target preference rank.

The `negotiation` microbenchmark begins with already validated
`CapabilityOffer` and `CapabilityPolicy` values and times
`negotiate_policy_permitted_common`.

Offer and policy construction are therefore excluded from the negotiation
microbenchmark but are included where specified in end-to-end establishment.

### 14.3 Common Protocol Fixture Values

Unless a later experiment explicitly varies one of these values, successful
profile comparisons use common protocol semantics:

~~~text
protocol identifier:  0x1300
protocol version:     1.0
client session bytes: [0x41; 16]
server session bytes: [0x42; 16]
client role:          Client
server role:          Server
~~~

Client and server policy identifiers remain endpoint-local and distinct.
Their numeric values must not be derived from the negotiated capability
identifier.

The application context and AAD are fixed byte strings shared across profile
comparisons.

### 14.4 Recipient Key Material

Recipient key material is generated or deterministically derived during
fixture preparation and outside timed activation regions.

Pure ML-KEM and hybrid profiles may require different implementation-level
key-derivation APIs. Those differences are normalized by fixture preparation
into serialized public and private material consumed by the public
secure-channel activation APIs.

Recipient key generation is not part of sender activation, receiver
activation, or initial end-to-end establishment measurements.

### 14.5 Randomness

Correctness fixtures may use deterministic test randomness when required for
repeatability.

Performance measurements of the production sender-activation API use
`rand_core::OsRng`. Randomness acquisition performed through the
`activate_sender` API is therefore part of sender-activation latency.

Benchmark code must not replace `activate_sender` with deterministic
lower-level HPKE setup merely to reduce timing variance.

Recipient key generation remains outside the timed region.

### 14.6 Initial Benchmark Matrix

The initial Criterion matrix is:

| Operation | Profiles | Initial timed boundary |
| --- | --- | --- |
| `negotiation` | all three | `negotiate_policy_permitted_common` |
| `profile_resolution` | all three | `resolve_hpke_profile` |
| `binding` | all three | `SecureChannelBinding::new` |
| `activate_sender` | all three | `activate_sender` |
| `activate_receiver` | all three | `activate_receiver` |
| `seal_1k` | all three | `SecureChannelSender::seal` |
| `open_1k` | all three | `SecureChannelReceiver::open` |
| `establish_channel` | all three | complete initial establishment workflow |

Criterion identifiers use the form:

~~~text
secure_channel/<operation>/<profile-label>
~~~

### 14.7 Microbenchmark Inputs

For `profile_resolution`, negotiation evidence is prepared outside the timed
region.

For `binding`, an `EstablishedProtocolContext` and application context are
prepared outside the timed region. The measurement includes allocation and
canonical serialization performed by `SecureChannelBinding::new`.

For `activate_sender`, the established client context, recipient public key,
and application context exist before timing begins. The timed call includes
profile resolution, binding construction, HPKE sender setup, production-path
randomness acquisition through the supplied RNG, and sender-context
construction.

For `activate_receiver`, the established server context, recipient private
material, application context, and valid encapsulated key exist before timing
begins. Sender activation used to create that encapsulated key is outside the
receiver timed region.

### 14.8 Protected-Message Batching

`seal_1k` and `open_1k` operate on fresh activated contexts supplied through
Criterion batched setup.

For `seal_1k`, channel activation occurs outside the timed routine and the
timed routine contains only the secure-channel `seal` call for the 1024-byte
payload and fixed AAD.

For `open_1k`, activation and preparation of a valid ciphertext occur outside
the timed routine and the timed routine contains only the secure-channel
`open` call.

Fresh contexts prevent sequence-number evolution across benchmark iterations
from changing measurement semantics.

### 14.9 Initial End-to-End Establishment Boundary

The initial `establish_channel` benchmark begins from caller-owned capability
identifier arrays, fixed protocol/session metadata, already provisioned
recipient key material, fixed application context, and an available
production RNG.

The timed workflow includes:

1. construction and validation of capability offers;
2. construction and validation of the resolved capability policy;
3. capability negotiation;
4. client and server typed-session construction;
5. transition into establishment;
6. establishment with retained negotiation evidence;
7. sender secure-channel activation;
8. receiver secure-channel activation.

Recipient key generation is excluded.

Protected-message `seal` and `open` operations are excluded and measured
separately.

The result must be a usable sender/receiver secure-channel pair authorized by
the expected negotiated capability.

### 14.10 Matched Lower-Layer Baselines

Existing HPKE benchmarks are not assumed to be cryptographically identical to
the negotiated secure-channel profiles. In particular, existing benchmark
suites may use different AEAD selections from the closed secure-channel
profiles.

Any paper result intended to quantify secure-channel integration overhead
relative to direct HPKE must therefore use a matched lower-layer baseline with
the same KEM, KDF, AEAD, payload, and otherwise relevant experimental
conditions.

Historical or unmatched HPKE benchmark results may be reported as contextual
lower-layer measurements but must not be used to derive a numerical
secure-channel overhead value.

## 15. E1e Correctness and Benchmark-Isolation Validation

E1e validates that the frozen benchmark matrix executes successfully in the
optimized benchmark configuration and that benchmark setup remains separated
from the intended timed regions.

This stage is a correctness and instrumentation gate. It does not collect
paper-facing performance results.

### 15.1 Optimized Criterion Smoke Validation

The secure-channel Criterion benchmark is executed in Criterion test mode:

~~~text
cargo bench \
  -p pqc-rs-secure-channel \
  --bench secure_channel \
  -- \
  --test
~~~

The smoke execution must succeed for all eight benchmark operations:

~~~text
negotiation
profile_resolution
binding
activate_sender
activate_receiver
seal_1k
open_1k
establish_channel
~~~

across all three registered secure-channel profiles:

~~~text
MLKEM768
MLKEM1024
MLKEM768-X25519
~~~

This produces 24 successful benchmark-path executions.

Criterion test mode is used only to confirm that optimized benchmark
binaries, fixtures, activation paths, and batched state preparation execute
successfully. Timing values from this gate are not treated as experimental
results.

### 15.2 Release-Mode Reference Workflow

The public-API reference workflow is also executed under the optimized release
profile:

~~~text
cargo test \
  -p pqc-rs-secure-channel \
  --release \
  --test reference_workflow
~~~

The workflow must succeed for all three registered profiles and verify
successful negotiation, establishment, sender activation, receiver activation,
1 KiB sealing, opening, and plaintext recovery.

### 15.3 Isolation Review

The benchmark source is reviewed against the E1b measurement contract.

The validated boundaries are:

- recipient key derivation occurs during fixture construction and is excluded
  from activation and establishment timing;
- the `negotiation` microbenchmark begins with validated
  `CapabilityOffer` and `CapabilityPolicy` values;
- `profile_resolution` begins with already negotiated capability evidence;
- `binding` begins with an already established protocol context;
- `activate_sender` begins with established context and provisioned recipient
  public material and includes production-path randomness acquisition;
- `activate_receiver` receives valid encapsulated material generated outside
  its timed routine;
- `seal_1k` uses Criterion batched setup to provide a fresh activated sender;
- `open_1k` uses Criterion batched setup to provide a fresh activated receiver
  and valid ciphertext;
- `establish_channel` includes capability-offer validation, policy validation,
  negotiation, typed-session establishment, sender activation, and receiver
  activation;
- `establish_channel` excludes recipient key derivation and protected-message
  operations.

The batched protected-message fixtures prevent channel sequence-number
evolution from changing benchmark semantics across iterations.

### 15.4 E1 Completion Gate

E1 is considered complete only when:

1. the experimental contract is frozen;
2. the benchmark matrix and fixture architecture are frozen;
3. the common reference workflow succeeds for all registered profiles;
4. all benchmark targets compile;
5. all 24 Criterion benchmark paths succeed in optimized test mode;
6. the release-mode reference workflow succeeds;
7. formatting, lint, documentation, and diff-hygiene checks pass.

Successful completion of E1 authorizes subsequent evaluation stages but does
not itself constitute paper-facing performance measurement.

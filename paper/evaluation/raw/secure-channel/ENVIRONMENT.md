# Secure-Channel Evaluation Environment

## Repository

Revision:

~~~text
4223700846625fb9bd584fd88c7c8233c2490bc1
~~~

Branch:

~~~text
feature/secure-channel-evaluation
~~~

Both `origin` and `public` pointed to the recorded revision before accepted
measurement collection began.

## Rust Toolchain

~~~text
rustc 1.89.0 (29483883e 2025-08-04)
cargo 1.89.0 (c24e10642 2025-06-23)
host: aarch64-apple-darwin
LLVM: 20.1.7
~~~

No explicit `RUSTFLAGS` or `CARGO_BUILD_RUSTFLAGS` were set.

No workspace Cargo profile overrides were present in the root manifest.

## Benchmark Harness

~~~text
Criterion 0.5.1
~~~

Benchmark target:

~~~text
pqc-rs-secure-channel / secure_channel
~~~

## Host Platform

~~~text
Model: MacBook Pro
Model identifier: Mac16,1
SoC: Apple M4
Architecture: arm64
CPU cores: 10
Memory: 24 GB
~~~

## Operating System

~~~text
macOS 26.5.2
Build 25F84
Darwin 25.5.0
~~~

## Power Configuration

Low-power mode was disabled for both battery and AC power at environment
capture time.

Accepted measurements should preferably be collected while connected to AC
power and with low-power mode disabled.

## Privacy

Hardware serial numbers, UUIDs, provisioning identifiers, and similar
device-specific identifiers are intentionally excluded because they are not
required for reproducibility.

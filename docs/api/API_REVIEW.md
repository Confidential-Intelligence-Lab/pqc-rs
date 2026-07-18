# B1.3.1 Public API Review

## Outcome

The workspace public surface was inventoried and classified before the production-hardening phase. The review intentionally avoids a broad breaking change. It establishes preferred interfaces, records compatibility debt, and creates an enforceable inventory.

## Primary finding

`HpkeSuite` validated a KEM/KDF/AEAD combination, but callers commonly converted it back to `HpkeSuiteId` before setup. The new suite-first setup functions retain the validated object throughout setup:

- `setup_base_sender_with_suite_deterministic`
- `setup_base_receiver_with_suite`
- `setup_psk_sender_with_suite_deterministic`
- `setup_psk_receiver_with_suite`

The existing identifier-based functions remain source-compatible wrappers.

## Compatibility findings

Several crates publicly expose implementation modules, and some crates retain placeholder marker types. Hiding or removing these symbols would be a breaking change. They are therefore classified in `API_INVENTORY.md` and deferred to a future major-version boundary.

## API policy established

New APIs should use validated domain types at protocol boundaries, avoid public fields unless representation is contractual, document errors and security-sensitive behavior, and preserve old entry points through wrappers when a non-breaking migration is practical.

## Validation

```bash
cargo xtask api-review
cargo xtask api-review --check
cargo doc --workspace --no-deps
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

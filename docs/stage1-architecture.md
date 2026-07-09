# Stage 1 Architecture

Stage 1 establishes the cryptographic library spine.

## Core traits

- `Kem`
- `SignatureScheme`
- `Encode`
- `Decode`

## Typed bytes

- `PublicKeyBytes<N>`
- `SecretKeyBytes<N>`
- `CiphertextBytes<N>`
- `SharedSecretBytes<N>`
- `SignatureBytes<N>`
- `ContextBytes<N>`

## Security defaults

- `forbid(unsafe_code)`
- secret material redacted from `Debug`
- secret material zeroized on drop
- shared secrets compared with `subtle::ConstantTimeEq`
- `no_std`-compatible core

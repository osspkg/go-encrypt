---
name: go-encrypt-usage
description: Use go.osspkg.com/encrypt from Go applications. Select the right AES-GCM, hash, OpenPGP, or PKI API and follow the library's input, key, nonce, and certificate contracts.
---

# go-encrypt usage

Use this skill when implementing code that imports `go.osspkg.com/encrypt` or when explaining how to use one of its packages.

## Workflow

1. Check the project's `go.mod` for the library version and Go version.
2. Identify the package needed and read its matching reference below. Read `pki.md` for certificate or OCSP work.
3. Follow the package contract in the reference; do not infer behavior from a similarly named API in another library.
4. Use a focused example as a starting point, then adapt names, key storage, error handling, and trust configuration to the application.
5. For code changes, run the relevant package tests and then the repository's documented checks.

## Package selection

- `aesgcm`: authenticated encryption for byte slices with AES-256-GCM.
- `hash`: adapt a Go `hash.Hash` to byte, string, reader, and value inputs.
- `pgp`: create OpenPGP keys and produce cleartext signatures.
- `pki`: create and persist X.509 certificates, CSRs, CRLs, and serve OCSP responses.

## Security and compatibility contracts

- Keep the entire AES-GCM value returned by `Encrypt`; it contains both the random nonce and authenticated ciphertext. Do not reuse or strip its nonce prefix.
- Create the hash implementation explicitly, such as `sha256.New()`. `WriteAny` hashes Go-formatted values; it is not a canonical encoding for durable identifiers or cross-language protocols. Prefer a specified byte encoding for those uses.
- OpenPGP keys are armored byte slices. `NewCert` may replace unsupported or weak requested hashes with SHA-256. Do not describe that fallback as the requested algorithm being used.
- Keep PKI private keys private. The library's `SaveKey` writes PKCS#8 PEM with restrictive permissions; certificate PEM is public data. Protect backups and any alternate key storage too.
- Treat OCSP requests and responses as network input/output. The HTTP handler enforces a 1 MiB request-body limit; resolvers should honor context cancellation and return a valid response or an error.
- Never claim a certificate is trusted merely because it was generated or parsed. Applications still need an appropriate trust store, hostname verification, validity checks, and revocation policy.

## References and examples

- [AES-GCM reference](references/aesgcm.md) · [runnable example](examples/aesgcm/main.go)
- [Hash reference](references/hash.md) · [runnable example](examples/hash/main.go)
- [OpenPGP reference](references/pgp.md) · [runnable example](examples/pgp/main.go)
- [PKI and OCSP reference](references/pki.md) · [runnable example](examples/pki/main.go)
- [Project README](../../README.md)
- [Go package documentation](https://pkg.go.dev/go.osspkg.com/encrypt)

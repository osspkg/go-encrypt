# go-encrypt

[![CI](https://github.com/osspkg/go-encrypt/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/osspkg/go-encrypt/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/go.osspkg.com/encrypt.svg)](https://pkg.go.dev/go.osspkg.com/encrypt)
[![License](https://img.shields.io/github/license/osspkg/go-encrypt)](LICENSE)

Cryptographic utilities for Go: AES-GCM encryption, OpenPGP key generation and
cleartext signatures, and X.509 certificate, CSR, CRL, and OCSP operations.

## Requirements

- Go 1.26 or newer

## Installation

```sh
go get go.osspkg.com/encrypt
```

Import the package you need, for example:

```go
import "go.osspkg.com/encrypt/aesgcm"
```

The examples below show function bodies. Add the package import for the example
and the standard-library imports referenced by its code.

## Packages

| Package | Purpose |
| --- | --- |
| [`aesgcm`](aesgcm) | AES-256-GCM authenticated encryption |
| [`hash`](hash) | Write byte streams and Go values to a `hash.Hash`; get binary, hex, or base64 digests |
| [`pgp`](pgp) | Generate armored OpenPGP key pairs and create cleartext signatures |
| [`pki`](pki) | Generate and encode X.509 keys, certificates, CSRs, and CRLs; serve OCSP responses |

## Usage

### AES-GCM

```go
key := make([]byte, 32)
if _, err := rand.Read(key); err != nil {
    return err
}

codec, err := aesgcm.New(key)
if err != nil {
    return err
}

ciphertext, err := codec.Encrypt([]byte("secret message"))
if err != nil {
    return err
}

plaintext, err := codec.Decrypt(ciphertext)
if err != nil {
    return err
}
_ = plaintext
```

`New` requires a 32-byte key and copies it. Each encryption generates a fresh
nonce and prepends it to the returned ciphertext; store or transmit the whole
slice so it can be decrypted. `Decrypt` returns an error if authentication
fails. Generate and protect keys with a cryptographically secure source.

### Hash values

```go
adapter := &hash.Adapter{H: sha256.New()}
if err := adapter.WriteString("message"); err != nil {
    return err
}
digest := adapter.ResultHex()
_ = digest
```

`WriteAny` hashes Go's formatted representation of each value; it is not a
canonical serialization format. Use a stable encoding when a digest must remain
reproducible across program or schema changes.

### OpenPGP signing

```go
keys, err := pgp.NewCert(pgp.Config{
    Name:  "Example User",
    Email: "user@example.com",
}, crypto.SHA256, 3072)
if err != nil {
    return err
}

signer := pgp.New()
if err := signer.SetKey(keys.Private, ""); err != nil {
    return err
}
var output bytes.Buffer
if err := signer.Sign(strings.NewReader("message to sign"), &output); err != nil {
    return err
}
```

`NewCert` returns armored public and private keys. Hashes unsupported or too
weak for key generation fall back to SHA-256. `NewCertSHA512` uses SHA-512 and a
4096-bit RSA key. Keep private keys protected and distribute only the public
key where needed.

### X.509 certificate authority

```go
ca, err := pki.NewCA(pki.Config{
    SignatureAlgorithm: x509.ECDSAWithSHA256,
    CommonName:         "Example Root CA",
}, 10*365*24*time.Hour, 1, 2)
if err != nil {
    return err
}
if err := ca.SaveKey("ca-key.pem"); err != nil {
    return err
}
if err := ca.SaveCert("ca-cert.pem"); err != nil {
    return err
}
```

Private keys are saved as PKCS #8 PEM with restrictive file permissions. Keep
CA keys offline or in a protected key store. `NewIntermediateCA` creates an
intermediate CA; `NewCRT` and `SignCSR` issue leaf certificates.

## Security notes

- `pki.OCSPServer.HTTPHandler` reads at most 1 MiB from each request body and
  returns HTTP 413 when the limit is exceeded.
- The `pgp` package uses the maintained ProtonMail OpenPGP implementation.
- Cryptographic operations do not replace key management, certificate
  validation, or application-specific security review.

## Contributing

Pull requests should include tests for behavior changes and pass the repository
checks. GitHub Actions runs `make ci` on pushes and pull requests to `master`.

## Development

Run Make targets from the repository root:

```sh
make tests
make lint
make build
```

`make lint` may update files; review `git diff` after running it. See
[AGENTS.md](AGENTS.md) for repository-specific development instructions.

## License

BSD 3-Clause. See [LICENSE](LICENSE).

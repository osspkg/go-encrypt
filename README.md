# go-encrypt

Cryptographic helpers for Go: AES-GCM encryption, OpenPGP key generation and
cleartext signatures, and X.509 certificate, CSR, CRL, and OCSP operations.

## Packages

- [`aesgcm`](./aesgcm): AES-256-GCM with a fresh nonce prepended to each
  ciphertext.
- [`hash`](./hash): write byte streams and Go values into a `hash.Hash` and
  retrieve the digest in binary, hexadecimal, or base64 form.
- [`pgp`](./pgp): generate OpenPGP key pairs and sign cleartext messages.
- [`pki`](./pki): create and encode X.509 keys, certificates, requests, and
  revocation data; serve OCSP responses.

## Install

```sh
go get go.osspkg.com/encrypt
```

The module requires Go 1.26 or newer.

## Examples

### AES-GCM

```go
package main

import (
	"crypto/rand"
	"fmt"

	"go.osspkg.com/encrypt/aesgcm"
)

func main() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	codec, err := aesgcm.New(key)
	if err != nil {
		panic(err)
	}

	ciphertext, err := codec.Encrypt([]byte("secret message"))
	if err != nil {
		panic(err)
	}
	plaintext, err := codec.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext))
}
```

Use a cryptographically random, unique key and protect it as a secret. The
returned ciphertext includes its nonce; store or transmit the complete byte
slice. Authentication failure makes `Decrypt` return an error. Do not reuse a
key with other encryption schemes unless their nonce and key requirements are
compatible.

### Create an X.509 CA

```go
package main

import (
	"crypto/x509"
	"time"

	"go.osspkg.com/encrypt/pki"
)

func main() {
	ca, err := pki.NewCA(pki.Config{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		CommonName:         "Example Root CA",
	}, 10*365*24*time.Hour, 1, 2)
	if err != nil {
		panic(err)
	}
	if err := ca.SaveKey("ca-key.pem"); err != nil {
		panic(err)
	}
	if err := ca.SaveCert("ca-cert.pem"); err != nil {
		panic(err)
	}
}
```

Private keys are saved as PKCS #8 PEM with restrictive file permissions. Keep
CA keys offline or in a protected key store. `NewCRT` and `SignCSR` issue leaf
certificates from a CA; `NewIntermediateCA` creates an intermediate CA.

## Notes

- `pgp.NewCert` accepts an OpenPGP hash and RSA key size. Unsupported or weak
  key-generation hashes are replaced with SHA-256. `pgp.NewCertSHA512` uses
  SHA-512 and a 4096-bit RSA key.
- `pki.OCSPServer.HTTPHandler` limits each request body to 1 MiB and returns
  HTTP 413 when the limit is exceeded.
- Cryptographic primitives are provided by Go's standard library and the
  maintained ProtonMail OpenPGP implementation.

## License

BSD 3-Clause. See [LICENSE](./LICENSE).

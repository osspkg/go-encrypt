# OpenPGP

Package: [`go.osspkg.com/encrypt/pgp`](https://pkg.go.dev/go.osspkg.com/encrypt/pgp)

`pgp.NewCert` creates armored public and private key data from a `pgp.Config`, hash, and RSA key size. The library substitutes SHA-256 when the requested key-generation hash is unsupported or too weak. Key generation is intentionally CPU intensive; generate keys as a provisioning operation and store the private armor in a secret store rather than generating a new identity for every request.

`pgp.New` returns a `Signer`, whose defaults are SHA-512 and 4096-bit RSA for generation/signing. Load private armored key bytes with `SetKey`, then use `Sign` to write an OpenPGP cleartext signature to an `io.Writer`. Pass the passphrase only when the private key is encrypted. Cleartext signatures include the signed text, so they are not detached signatures.

```go
cert, err := pgp.NewCert(pgp.Config{
	Name:  "Example Service",
	Email: "service@example.test",
}, crypto.SHA256, 3072)
if err != nil {
	return err
}

signer := pgp.New()
if err := signer.SetKey(cert.Private, ""); err != nil {
	return err
}
var signed bytes.Buffer
if err := signer.Sign(strings.NewReader("release metadata\n"), &signed); err != nil {
	return err
}
```

Validate signatures and signer identity at the receiving side using the OpenPGP implementation and trust policy appropriate to the application. Do not treat parsing a public key as proof that the key belongs to a trusted identity.

Run the example with `go run ./skills/go-encrypt-usage/examples/pgp` from the module root.

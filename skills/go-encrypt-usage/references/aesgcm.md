# AES-GCM

Package: [`go.osspkg.com/encrypt/aesgcm`](https://pkg.go.dev/go.osspkg.com/encrypt/aesgcm)

`aesgcm.New` accepts exactly a 32-byte AES-256 key and copies it into a `Codec`. Keep the key secret for the lifetime of the codec. `Encrypt` generates a fresh cryptographically random nonce for each call and prefixes it to the authenticated ciphertext. Persist or transmit the complete returned slice. `Decrypt` expects exactly that combined representation and reports an error for truncated or modified data.

```go
key := make([]byte, 32)
if _, err := rand.Read(key); err != nil {
	return err
}
codec, err := aesgcm.New(key)
if err != nil {
	return err
}

sealed, err := codec.Encrypt([]byte("message"))
if err != nil {
	return err
}
plain, err := codec.Decrypt(sealed)
if err != nil {
	return err
}
_ = plain
```

Use an established key-management mechanism to provision and rotate keys. The example generates a key only to demonstrate the API; production services should not generate an unrelated new key on each process start if they need to decrypt previously stored data.

Run the example with `go run ./skills/go-encrypt-usage/examples/aesgcm` from the module root.

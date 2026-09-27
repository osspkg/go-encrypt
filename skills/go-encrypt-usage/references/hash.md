# Hash adapters

Package: [`go.osspkg.com/encrypt/hash`](https://pkg.go.dev/go.osspkg.com/encrypt/hash)

Initialize `hash.Adapter.H` with the desired implementation before calling methods. The adapter supports writing bytes, strings, readers, or values, and returning the digest as bytes, hexadecimal, or Base64. Call `Reset` before reusing an adapter for a separate digest.

For stable digests, define the algorithm and byte representation as part of the protocol. `WriteAny` accepts supported Go values but formats them using Go representation; map formatting, type changes, and application-version changes make it unsuitable as a canonical cross-process or cross-language serialization format. Encode values explicitly (for example, with a documented schema) and write the resulting bytes instead.

```go
sum := hash.Adapter{H: sha256.New()}
if err := sum.WriteString("payload"); err != nil {
	return err
}
fmt.Println(sum.ResultHex())
```

Run the example with `go run ./skills/go-encrypt-usage/examples/hash` from the module root.

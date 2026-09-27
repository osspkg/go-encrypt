# X.509 PKI and OCSP

Package: [`go.osspkg.com/encrypt/pki`](https://pkg.go.dev/go.osspkg.com/encrypt/pki)

## Creating certificates

`pki.NewCA` creates a CA key/certificate pair. `intermediateCount` configures the permitted CA path length; use the smallest value consistent with the intended hierarchy. `pki.NewCRT` creates a leaf certificate signed by a CA. Set a short, deliberate validity interval and unique positive serial numbers. Validate SANs, key usages, validity, and the trust chain when consuming certificates.

```go
root, err := pki.NewCA(pki.Config{
	SignatureAlgorithm: x509.ECDSAWithSHA256,
	CommonName:         "Example Root CA",
}, 10*365*24*time.Hour, 1, 0)
if err != nil {
	return err
}

leaf, err := pki.NewCRT(pki.Config{
	SignatureAlgorithm: x509.ECDSAWithSHA256,
	CommonName:         "service.example.test",
}, *root, 90*24*time.Hour, 2, "service.example.test")
if err != nil {
	return err
}
_ = leaf
```

`Certificate.SaveKey` writes PKCS#8 PEM with restrictive file permissions; `SaveCert` writes the public certificate PEM. Check and propagate persistence errors. Protect private-key copies, backups, and directory permissions. `NewCSR` and `SignCSR` support a flow where a requester creates a CSR and a CA signs it; verify the CSR signature and apply issuance policy before signing.

## OCSP HTTP handler

`OCSPServer` is configured with its CA and a resolver, then exposes `HTTPHandler()`. Implement the resolver using request context so canceled clients do not leave work running. Return an OCSP response for the request or an error; configure `OnError` for operational reporting. The handler caps request bodies at 1 MiB and rejects oversized requests.

```go
server := &pki.OCSPServer{
	CA:       ca,
	Resolver: resolver,
	OnError:  func(err error) { logger.Error("OCSP request failed", "err", err) },
}
mux.HandleFunc("/ocsp", server.HTTPHandler)
```

See the package documentation for the exact resolver and OCSP response contracts. Expose the endpoint only with the transport and monitoring controls required by the deployment.

Run the certificate example with `go run ./skills/go-encrypt-usage/examples/pki` from the module root.

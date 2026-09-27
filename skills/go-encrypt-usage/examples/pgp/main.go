package main

import (
	"bytes"
	"crypto"
	"fmt"
	"strings"

	"go.osspkg.com/encrypt/pgp"
)

func main() {
	cert, err := pgp.NewCert(pgp.Config{
		Name:  "Example Service",
		Email: "service@example.test",
	}, crypto.SHA256, 3072)
	if err != nil {
		panic(err)
	}

	signer := pgp.New()
	if err := signer.SetKey(cert.Private, ""); err != nil {
		panic(err)
	}

	var signed bytes.Buffer
	if err := signer.Sign(strings.NewReader("release metadata\n"), &signed); err != nil {
		panic(err)
	}
	fmt.Printf("created cleartext signature (%d bytes)\n", signed.Len())
}

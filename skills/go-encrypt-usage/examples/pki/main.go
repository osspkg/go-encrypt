package main

import (
	"crypto/x509"
	"fmt"
	"time"

	"go.osspkg.com/encrypt/pki"
)

func main() {
	root, err := pki.NewCA(pki.Config{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		CommonName:         "Example Root CA",
	}, 10*365*24*time.Hour, 1, 0)
	if err != nil {
		panic(err)
	}

	leaf, err := pki.NewCRT(pki.Config{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		CommonName:         "service.example.test",
	}, *root, 90*24*time.Hour, 2, "service.example.test")
	if err != nil {
		panic(err)
	}
	fmt.Printf("issued certificate for %s\n", leaf.Crt.Subject.CommonName)
}

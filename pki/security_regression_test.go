package pki_test

import (
	"crypto/x509"
	"testing"
	"time"

	"go.osspkg.com/encrypt/pki"
)

func TestSignCSRRejectsInvalidSignature(t *testing.T) {
	root, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, 24*time.Hour, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	request, err := pki.NewCSR(x509.ECDSAWithSHA256, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	request.Csr.RawTBSCertificateRequest[0] ^= 1

	if _, err := pki.SignCSR(pki.Config{}, *root, *request.Csr, time.Hour, 2); err == nil {
		t.Fatal("SignCSR accepted a CSR with an invalid signature")
	}
}

func TestNewCSRRejectsMalformedIPWithPort(t *testing.T) {
	if _, err := pki.NewCSR(x509.ECDSAWithSHA256, "not-an-ip:443"); err == nil {
		t.Fatal("NewCSR accepted an invalid IP address")
	}
}

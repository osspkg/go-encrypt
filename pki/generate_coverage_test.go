package pki_test

import (
	"crypto/x509"
	"testing"
	"time"

	"go.osspkg.com/encrypt/pki"
)

func TestCRLAndGenerationFailures(t *testing.T) {
	ca, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, time.Hour*48, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := pki.NewCRL(*ca, 1, time.Hour, []pki.RevocationEntity{{SerialNumber: 4, RevocationTime: time.Now()}})
	if err != nil || len(crl) == 0 {
		t.Fatalf("NewCRL len=%d err=%v", len(crl), err)
	}
	if _, err := pki.NewCRL(pki.Certificate{}, 1, time.Hour, nil); err == nil {
		t.Fatal("NewCRL accepted invalid CA")
	}
	if _, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.UnknownSignatureAlgorithm}, time.Hour, 1, 0); err == nil {
		t.Fatal("NewCA accepted unknown algorithm")
	}
	if _, err := pki.NewCSR(x509.UnknownSignatureAlgorithm, "host.test"); err == nil {
		t.Fatal("NewCSR accepted unknown algorithm")
	}
	if _, err := pki.NewCSR(x509.ECDSAWithSHA256); err == nil {
		t.Fatal("NewCSR accepted no domains")
	}
	if _, err := pki.NewCRT(pki.Config{}, pki.Certificate{}, time.Hour, 1, "host.test"); err == nil {
		t.Fatal("NewCRT accepted invalid CA")
	}
	if _, err := pki.NewIntermediateCA(pki.Config{}, pki.Certificate{}, time.Hour, 1); err == nil {
		t.Fatal("NewIntermediateCA accepted invalid CA")
	}
}

func TestRSAPSSKeyGeneration(t *testing.T) {
	request, err := pki.NewCSR(x509.SHA256WithRSAPSS, "pss.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if request.Key == nil || request.Csr == nil {
		t.Fatal("NewCSR returned incomplete RSA-PSS request")
	}
}

func TestGenerationPathAndSigningErrors(t *testing.T) {
	root, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, 24*time.Hour, 60, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.NewIntermediateCA(pki.Config{}, *root, time.Hour, 61); err == nil {
		t.Fatal("intermediate exceeded root path length")
	}
	rootWithPath, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, time.Hour, 62, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.NewIntermediateCA(pki.Config{}, *rootWithPath, 2*time.Hour, 63); err == nil {
		t.Fatal("intermediate validity exceeded issuer validity")
	}
	if _, err := pki.NewCRT(pki.Config{SignatureAlgorithm: x509.UnknownSignatureAlgorithm}, *rootWithPath, time.Minute, 64, "host.test"); err == nil {
		t.Fatal("NewCRT accepted unknown signature algorithm")
	}
	if _, err := pki.NewCRT(pki.Config{}, *rootWithPath, time.Hour, 65, "bad-ip:443"); err == nil {
		t.Fatal("NewCRT accepted malformed host:port")
	}
	csr, err := pki.NewCSR(x509.ECDSAWithSHA256, "sign.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.SignCSR(pki.Config{SignatureAlgorithm: x509.UnknownSignatureAlgorithm}, *rootWithPath, *csr.Csr, time.Minute, 66); err == nil {
		t.Fatal("SignCSR accepted unknown algorithm")
	}
	if _, err := pki.SignCSR(pki.Config{}, pki.Certificate{}, *csr.Csr, time.Minute, 67); err == nil {
		t.Fatal("SignCSR accepted invalid CA")
	}
}

func TestGenerationInvalidDatesAndAlgorithms(t *testing.T) {
	if _, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, time.Hour, -1, 0); err == nil {
		t.Fatal("NewCA accepted negative serial")
	}
	root, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, 24*time.Hour, 71, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.NewIntermediateCA(pki.Config{SignatureAlgorithm: x509.SignatureAlgorithm(999)}, *root, time.Hour, 72); err == nil {
		t.Fatal("NewIntermediateCA accepted unknown algorithm")
	}
	if _, err := pki.NewCRT(pki.Config{}, *root, 48*time.Hour, 73, "long.example.test"); err == nil {
		t.Fatal("NewCRT exceeded issuer validity")
	}
	if _, err := pki.NewCRT(pki.Config{SignatureAlgorithm: x509.SignatureAlgorithm(999)}, *root, time.Hour, 74, "unknown.example.test"); err == nil {
		t.Fatal("NewCRT accepted unknown algorithm")
	}
	if _, err := pki.NewCSR(x509.SignatureAlgorithm(999), "unknown.example.test"); err == nil {
		t.Fatal("NewCSR accepted unknown algorithm")
	}
	request, err := pki.NewCSR(x509.ECDSAWithSHA256, "csr.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.SignCSR(pki.Config{SignatureAlgorithm: x509.SignatureAlgorithm(999)}, *root, *request.Csr, time.Hour, 75); err == nil {
		t.Fatal("SignCSR accepted unknown algorithm")
	}
}

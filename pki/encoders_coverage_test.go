package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"go.osspkg.com/encrypt/pki"
)

//nolint:revive // This test groups related coverage cases for one API.
func TestEncodersRoundTrip(t *testing.T) {
	keyCert, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256, CommonName: "root"}, 24*time.Hour, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := pki.MarshalKeyDER(keyCert.Key)
	if err != nil {
		t.Fatal(err)
	}
	keyFromDER, err := pki.UnmarshalKeyDER(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := pki.MarshalKeyPEM(keyFromDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalKeyPEM(keyPEM); err != nil {
		t.Fatal(err)
	}

	certDER := pki.MarshalCrtDER(*keyCert.Crt)
	if _, err := pki.UnmarshalCrtDER(certDER); err != nil {
		t.Fatal(err)
	}
	certPEM, err := pki.MarshalCrtPEM(*keyCert.Crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalCrtPEM(certPEM); err != nil {
		t.Fatal(err)
	}

	request, err := pki.NewCSR(x509.ECDSAWithSHA256, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	csrDER := pki.MarshalCsrDER(*request.Csr)
	if _, err := pki.UnmarshalCsrDER(csrDER); err != nil {
		t.Fatal(err)
	}
	csrPEM, err := pki.MarshalCsrPEM(*request.Csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalCsrPEM(csrPEM); err != nil {
		t.Fatal(err)
	}

	customPEM := pki.CreatePEMBlock([]byte("data"), pki.PrivateKeyPEMBlock, "ENCRYPTED")
	block, _ := pem.Decode(customPEM)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("unexpected PEM type: %#v", block)
	}
}

func TestEncodersRejectInvalidInput(t *testing.T) {
	if _, err := pki.MarshalKeyDER(nil); err == nil {
		t.Fatal("MarshalKeyDER accepted nil key")
	}
	for name, fn := range map[string]func([]byte) error{
		"key DER":  func(b []byte) error { _, err := pki.UnmarshalKeyDER(b); return err },
		"key PEM":  func(b []byte) error { _, err := pki.UnmarshalKeyPEM(b); return err },
		"cert DER": func(b []byte) error { _, err := pki.UnmarshalCrtDER(b); return err },
		"cert PEM": func(b []byte) error { _, err := pki.UnmarshalCrtPEM(b); return err },
		"CSR DER":  func(b []byte) error { _, err := pki.UnmarshalCsrDER(b); return err },
		"CSR PEM":  func(b []byte) error { _, err := pki.UnmarshalCsrPEM(b); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := fn([]byte("bad")); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}

	_, err := pki.UnmarshalKeyDER([]byte{0x30, 0x00})
	if err == nil {
		t.Fatal("UnmarshalKeyDER accepted non-key PKCS#8")
	}
}

//nolint:revive // This test groups related coverage cases for one API.
func TestCertificateAndRequestFiles(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, 24*time.Hour, 11, 0)
	if err != nil {
		t.Fatal(err)
	}
	certKeyPath, certPath := dir+"/key.pem", dir+"/cert.pem"
	if err := ca.SaveKey(certKeyPath); err != nil {
		t.Fatal(err)
	}
	if err := ca.SaveCert(certPath); err != nil {
		t.Fatal(err)
	}
	var loaded pki.Certificate
	if err := loaded.LoadKey(certKeyPath); err != nil {
		t.Fatal(err)
	}
	if err := loaded.LoadCert(certPath); err != nil {
		t.Fatal(err)
	}
	if !loaded.IsValidPair() {
		t.Fatal("saved certificate and key do not match")
	}

	csr, err := pki.NewCSR(x509.ECDSAWithSHA256, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	requestKeyPath, requestPath := dir+"/request-key.pem", dir+"/request.pem"
	if err := csr.SaveKey(requestKeyPath); err != nil {
		t.Fatal(err)
	}
	if err := csr.SaveCert(requestPath); err != nil {
		t.Fatal(err)
	}
	var loadedRequest pki.Request
	if err := loadedRequest.LoadKey(requestKeyPath); err != nil {
		t.Fatal(err)
	}
	if err := loadedRequest.LoadCert(requestPath); err != nil {
		t.Fatal(err)
	}
	if loadedRequest.Csr.Subject.CommonName != "example.test" {
		t.Fatalf("unexpected CSR: %q", loadedRequest.Csr.Subject.CommonName)
	}

	if err := (*pki.Certificate)(nil).SaveKey(certKeyPath); err == nil {
		t.Fatal("nil certificate saved a key")
	}
	if err := (*pki.Certificate)(nil).SaveCert(certPath); err == nil {
		t.Fatal("nil certificate saved a cert")
	}
	if err := (*pki.Request)(nil).SaveKey(requestKeyPath); err == nil {
		t.Fatal("nil request saved a key")
	}
	if err := (*pki.Request)(nil).SaveCert(requestPath); err == nil {
		t.Fatal("nil request saved a CSR")
	}
	if err := loaded.LoadKey(dir + "/missing"); err == nil {
		t.Fatal("LoadKey accepted missing file")
	}
	if err := loaded.LoadCert(dir + "/missing"); err == nil {
		t.Fatal("LoadCert accepted missing file")
	}
	if err := loadedRequest.LoadKey(dir + "/missing"); err == nil {
		t.Fatal("Request.LoadKey accepted missing file")
	}
	if err := loadedRequest.LoadCert(dir + "/missing"); err == nil {
		t.Fatal("Request.LoadCert accepted missing file")
	}
}

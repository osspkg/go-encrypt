package pki_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.osspkg.com/encrypt/pki"
)

//nolint:revive // This test groups related coverage cases for one API.
func TestCertificateMetadataAndFileModes(t *testing.T) {
	ca, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256, CommonName: "Coverage Root"}, time.Hour, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
		if _, err := ca.FingerPrint(hash); err != nil {
			t.Errorf("FingerPrint: %v", err)
		}
		if _, err := ca.IssuerKeyHash(hash); err != nil {
			t.Errorf("IssuerKeyHash: %v", err)
		}
		if _, err := ca.IssuerNameHash(hash); err != nil {
			t.Errorf("IssuerNameHash: %v", err)
		}
	}
	if _, err := ca.FingerPrint(crypto.Hash(0)); err == nil {
		t.Fatal("FingerPrint accepted unknown hash")
	}
	if _, err := ca.IssuerKeyHash(crypto.Hash(0)); err == nil {
		t.Fatal("IssuerKeyHash accepted unknown hash")
	}
	if _, err := ca.IssuerNameHash(crypto.Hash(0)); err == nil {
		t.Fatal("IssuerNameHash accepted unknown hash")
	}
	if (*pki.Certificate)(nil).IsCA() || (*pki.Certificate)(nil).IsValidPair() {
		t.Fatal("nil certificate reported valid")
	}
	if (&pki.Certificate{}).IsCA() || (&pki.Certificate{}).IsValidPair() {
		t.Fatal("empty certificate reported valid")
	}
	if (&pki.Certificate{Crt: ca.Crt}).IsValidPair() {
		t.Fatal("certificate without key reported valid")
	}

	dir := t.TempDir()
	keyPath, crtPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	if err := ca.SaveKey(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := ca.SaveCert(crtPath); err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions = %o", keyInfo.Mode().Perm())
	}
	crtInfo, err := os.Stat(crtPath)
	if err != nil {
		t.Fatal(err)
	}
	if crtInfo.Mode().Perm() != 0o644 {
		t.Fatalf("certificate permissions = %o", crtInfo.Mode().Perm())
	}
}

//nolint:revive // This test groups related coverage cases for one API.
func TestCertificateFileLoadingDERAndInvalidData(t *testing.T) {
	ca, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, time.Hour, 21, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyDER, err := pki.MarshalKeyDER(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	crtDER := pki.MarshalCrtDER(*ca.Crt)
	keyPath, crtPath := filepath.Join(dir, "key.der"), filepath.Join(dir, "cert.der")
	if err := os.WriteFile(keyPath, keyDER, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crtPath, crtDER, 0o600); err != nil {
		t.Fatal(err)
	}
	var loaded pki.Certificate
	if err := loaded.LoadKey(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := loaded.LoadCert(crtPath); err != nil {
		t.Fatal(err)
	}
	badKey, badCert := filepath.Join(dir, "bad-key"), filepath.Join(dir, "bad-cert")
	if err := os.WriteFile(badKey, []byte("invalid DER"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badCert, []byte("invalid DER"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loaded.LoadKey(badKey); err == nil {
		t.Fatal("LoadKey accepted invalid DER")
	}
	if err := loaded.LoadCert(badCert); err == nil {
		t.Fatal("LoadCert accepted invalid DER")
	}
}

func TestRequestFileErrors(t *testing.T) {
	request, err := pki.NewCSR(x509.ECDSAWithSHA256, "load.example.test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath, csrPath := filepath.Join(dir, "bad-key.pem"), filepath.Join(dir, "bad-request.pem")
	if err := os.WriteFile(keyPath, []byte("not a PEM key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(csrPath, []byte("not a PEM request"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := request.LoadKey(keyPath); err == nil {
		t.Fatal("Request.LoadKey accepted invalid PEM")
	}
	if err := request.LoadCert(csrPath); err == nil {
		t.Fatal("Request.LoadCert accepted invalid PEM")
	}
	missingParent := filepath.Join(dir, "missing", "key.pem")
	if err := request.SaveKey(missingParent); err == nil {
		t.Fatal("Request.SaveKey accepted missing directory")
	}
	if err := request.SaveCert(missingParent); err == nil {
		t.Fatal("Request.SaveCert accepted missing directory")
	}
}

func TestCertificateNilAndMalformedMetadata(t *testing.T) {
	var cert *pki.Certificate
	if _, err := cert.FingerPrint(crypto.SHA256); err == nil {
		t.Fatal("FingerPrint accepted nil certificate")
	}
	if _, err := cert.IssuerKeyHash(crypto.SHA256); err == nil {
		t.Fatal("IssuerKeyHash accepted nil certificate")
	}
	if _, err := cert.IssuerNameHash(crypto.SHA256); err == nil {
		t.Fatal("IssuerNameHash accepted nil certificate")
	}
	malformed := &pki.Certificate{Crt: &x509.Certificate{RawSubjectPublicKeyInfo: []byte{0xff}}}
	if _, err := malformed.IssuerKeyHash(crypto.SHA256); err == nil {
		t.Fatal("IssuerKeyHash accepted malformed SPKI")
	}
	if (&pki.Certificate{Key: ed25519PrivateKey(t), Crt: &x509.Certificate{}}).IsValidPair() {
		t.Fatal("unsupported private key matched certificate")
	}
}

func ed25519PrivateKey(t *testing.T) crypto.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

package pgp_test

import (
	"bytes"
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"go.osspkg.com/encrypt/pgp"
)

//nolint:revive // This test groups related coverage cases for one API.
func TestSignerKeyExportHeadersAndSigning(t *testing.T) {
	cert, err := pgp.NewCertSHA512(pgp.Config{Name: "Coverage", Email: "coverage@example.test"}, "Client", "Unit Test")
	if err != nil {
		t.Fatal(err)
	}
	signer := pgp.New()
	if err := signer.Sign(bytes.NewReader(nil), &bytes.Buffer{}); err == nil {
		t.Fatal("Sign succeeded without a key")
	}
	if _, err := signer.PublicKey(); err == nil {
		t.Fatal("PublicKey succeeded without a key")
	}
	if _, err := signer.PublicKeyBase64(); err == nil {
		t.Fatal("PublicKeyBase64 succeeded without a key")
	}
	headerSigner, ok := signer.(interface{ SetHeaders(headers ...string) error })
	if !ok {
		t.Fatal("signer does not support armor headers")
	}
	if err := headerSigner.SetHeaders("odd"); err == nil {
		t.Fatal("SetHeaders accepted an odd number of values")
	}
	if err := headerSigner.SetHeaders("Client", "Coverage Test"); err != nil {
		t.Fatal(err)
	}
	if err := signer.SetKey(cert.Private, ""); err != nil {
		t.Fatal(err)
	}

	binary, err := signer.PublicKey()
	if err != nil || len(binary) == 0 {
		t.Fatalf("PublicKey: len=%d err=%v", len(binary), err)
	}
	armored, err := signer.PublicKeyBase64()
	if err != nil || !bytes.Contains(armored, []byte("Client: Unit Test")) {
		t.Fatalf("PublicKeyBase64: err=%v output=%q", err, armored)
	}
	var signed bytes.Buffer
	if err := signer.Sign(strings.NewReader("signed message"), &signed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed.Bytes(), []byte("BEGIN PGP SIGNED MESSAGE")) {
		t.Fatalf("unexpected cleartext signature: %q", signed.String())
	}

	path := filepath.Join(t.TempDir(), "private.asc")
	if err := os.WriteFile(path, cert.Private, 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile := pgp.New()
	if err := fromFile.SetKeyFromFile(path, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := fromFile.PublicKey(); err != nil {
		t.Fatal(err)
	}
	if err := fromFile.SetKeyFromFile(path+".missing", ""); err == nil {
		t.Fatal("SetKeyFromFile accepted missing file")
	}
}

func TestSignerRejectsMalformedAndEncryptedKeys(t *testing.T) {
	signer := pgp.New()
	if _, err := pgp.NewCert(pgp.Config{}, crypto.SHA256, 1024, "odd"); err == nil {
		t.Fatal("NewCert accepted an odd number of armor header values")
	}
	if _, err := pgp.NewCert(pgp.Config{}, crypto.SHA256, 512); err == nil {
		t.Fatal("NewCert accepted invalid RSA bit size")
	}
	if err := signer.SetKey([]byte("invalid"), ""); err == nil {
		t.Fatal("SetKey accepted invalid armor")
	}
	if err := signer.SetKey([]byte("-----BEGIN PGP MESSAGE-----\n\nAA==\n-----END PGP MESSAGE-----"), ""); err == nil {
		t.Fatal("SetKey accepted non-private-key armor")
	}

	cert, err := pgp.NewCert(pgp.Config{Name: "Encrypted"}, crypto.SHA256, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.SetKey(cert.Private, "wrong"); err != nil {
		t.Fatalf("unencrypted key should not need password: %v", err)
	}
	if err := signer.Sign(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("Sign accepted nil reader")
	}
}

func TestSignerRejectsEmptyKeyring(t *testing.T) {
	var armored bytes.Buffer
	enc, err := armor.Encode(&armored, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pgp.New().SetKey(armored.Bytes(), ""); err == nil {
		t.Fatal("SetKey accepted an empty keyring")
	}
}

//nolint:testpackage // These tests need package-private helpers and data structures.
package pgp

import (
	"bytes"
	"crypto"
	"errors"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type failedSeek struct{ *bytes.Reader }

func (failedSeek) Seek(int64, int) (int64, error) { return 0, errors.New("seek failed") }

func encryptedPrivateArmor(t *testing.T, password string) []byte {
	t.Helper()
	entity, err := openpgp.NewEntity("encrypted", "", "encrypted@example.test", &packet.Config{RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}
	conf := &packet.Config{DefaultHash: crypto.SHA256}
	if err := setupIdentities(entity, conf); err != nil {
		t.Fatal(err)
	}
	if err := entity.PrivateKey.Encrypt([]byte(password)); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	enc, err := armor.Encode(&output, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivateWithoutSigning(enc, conf); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestReadKeyEncryptedAndSeekFailure(t *testing.T) {
	encoded := encryptedPrivateArmor(t, "correct")
	signer, ok := New().(*store)
	if !ok {
		t.Fatal("New returned unexpected signer implementation")
	}
	if err := signer.SetKey(encoded, "wrong"); err == nil {
		t.Fatal("SetKey accepted wrong passphrase")
	}
	if err := signer.SetKey(encoded, "correct"); err != nil {
		t.Fatal(err)
	}
	if err := signer.readKey(failedSeek{bytes.NewReader(encoded)}, "correct"); err == nil {
		t.Fatal("readKey ignored seek failure")
	}
}

func TestArmorAndSigningWriterFailures(t *testing.T) {
	entity, err := openpgp.NewEntity("writer", "", "writer@example.test", &packet.Config{RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if err := generatePrivateKey(entity, failingWriter{}, nil); err == nil {
		t.Fatal("generatePrivateKey ignored writer failure")
	}
	if err := generatePublicKey(entity, failingWriter{}, nil); err == nil {
		t.Fatal("generatePublicKey ignored writer failure")
	}

	signer, ok := New().(*store)
	if !ok {
		t.Fatal("New returned unexpected signer implementation")
	}
	signer.key = entity
	if err := signer.Sign(bytes.NewBufferString("message"), failingWriter{}); err == nil {
		t.Fatal("Sign ignored writer failure")
	}
	if err := signer.Sign(failingReader{}, &bytes.Buffer{}); err == nil {
		t.Fatal("Sign ignored reader failure")
	}
}

var _ io.Writer = failingWriter{}

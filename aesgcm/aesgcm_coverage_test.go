package aesgcm_test

import (
	"bytes"
	"testing"

	"go.osspkg.com/encrypt/aesgcm"
)

func TestCodecRejectsInvalidKeyAndCiphertext(t *testing.T) {
	if _, err := aesgcm.New(make([]byte, 31)); err == nil {
		t.Fatal("New accepted a key with the wrong length")
	}
	codec, err := aesgcm.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decrypt(make([]byte, 11)); err == nil {
		t.Fatal("Decrypt accepted ciphertext shorter than a nonce")
	}
	ciphertext, err := codec.Encrypt([]byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := codec.Decrypt(ciphertext); err == nil {
		t.Fatal("Decrypt accepted modified ciphertext")
	}
	first, err := codec.Encrypt(nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := codec.Encrypt(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("Encrypt reused a nonce for identical plaintext")
	}
}

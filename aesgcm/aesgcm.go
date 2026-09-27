/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

// Package aesgcm provides AES-GCM authenticated encryption.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"go.osspkg.com/random"
)

const keySize = 32

// Codec provides authenticated encryption and decryption with AES-GCM. Create
// it with New; it retains a copy of the key for its lifetime.
type Codec struct {
	key   []byte
	block cipher.Block
}

// New creates an AES-GCM codec for a 256-bit key. It copies key so the caller
// can safely reuse or modify the input slice after New returns.
func New(key []byte) (*Codec, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid key len, want %d got %d", keySize, len(key))
	}
	obj := &Codec{
		key: make([]byte, keySize),
	}
	copy(obj.key, key)
	block, err := aes.NewCipher(obj.key)
	if err != nil {
		return nil, err
	}
	obj.block = block
	return obj, nil
}

// Encrypt encrypts plaintext and prepends a fresh, cryptographically random
// nonce to the ciphertext. Store or transmit the entire returned slice so the
// nonce is available to Decrypt. A new nonce is generated for every call.
func (v *Codec) Encrypt(plaintext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(v.block)
	if err != nil {
		return nil, err
	}
	nonce := random.CryptoBytes(gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt authenticates and decrypts ciphertext produced by Encrypt. It returns
// an error if ciphertext is shorter than the nonce or fails authentication.
func (v *Codec) Decrypt(ciphertext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(v.block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("invalid message len")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

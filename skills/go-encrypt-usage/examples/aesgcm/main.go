/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

// Package main demonstrates AES-GCM encryption and decryption.
package main

import (
	"crypto/rand"
	"fmt"

	"go.osspkg.com/encrypt/aesgcm"
)

const keySize = 32 // AES-256 key size in bytes.

func main() {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	codec, err := aesgcm.New(key)
	if err != nil {
		panic(err)
	}

	sealed, err := codec.Encrypt([]byte("secret message"))
	if err != nil {
		panic(err)
	}
	plain, err := codec.Decrypt(sealed)
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted: %s\n", plain)
}

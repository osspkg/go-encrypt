/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

// Package main demonstrates hashing a string with SHA-256.
package main

import (
	"crypto/sha256"
	"fmt"

	"go.osspkg.com/encrypt/hash"
)

func main() {
	digest := hash.Adapter{H: sha256.New()}
	if err := digest.WriteString("payload"); err != nil {
		panic(err)
	}
	fmt.Println(digest.ResultHex())
}

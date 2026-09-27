/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

// Package main demonstrates generating a key and signing a message with OpenPGP.
package main

import (
	"bytes"
	"crypto"
	"fmt"
	"strings"

	"go.osspkg.com/encrypt/pgp"
)

const rsaKeySize = 3072

func main() {
	cert, err := pgp.NewCert(pgp.Config{
		Name:  "Example Service",
		Email: "service@example.test",
	}, crypto.SHA256, rsaKeySize)
	if err != nil {
		panic(err)
	}

	signer := pgp.New()
	if err := signer.SetKey(cert.Private, ""); err != nil {
		panic(err)
	}

	var signed bytes.Buffer
	if err := signer.Sign(strings.NewReader("release metadata\n"), &signed); err != nil {
		panic(err)
	}
	fmt.Printf("created cleartext signature (%d bytes)\n", signed.Len())
}

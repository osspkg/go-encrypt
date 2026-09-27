/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

// Package main demonstrates creating a root CA and issuing a leaf certificate.
package main

import (
	"crypto/x509"
	"fmt"
	"time"

	"go.osspkg.com/encrypt/pki"
)

const (
	rootSerialNumber = 1
	leafSerialNumber = 2
	caPathLength     = 0
)

func main() {
	root, err := pki.NewCA(pki.Config{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		CommonName:         "Example Root CA",
	}, 10*365*24*time.Hour, rootSerialNumber, caPathLength)
	if err != nil {
		panic(err)
	}

	leaf, err := pki.NewCRT(pki.Config{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		CommonName:         "service.example.test",
	}, *root, 90*24*time.Hour, leafSerialNumber, "service.example.test")
	if err != nil {
		panic(err)
	}
	fmt.Printf("issued certificate for %s\n", leaf.Crt.Subject.CommonName)
}

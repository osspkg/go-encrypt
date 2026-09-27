/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"
)

type RevocationEntity struct {
	SerialNumber   int64     `json:"serial_number"   yaml:"serial_number"`
	RevocationTime time.Time `json:"revocation_time" yaml:"revocation_time"`
}

func NewCRL(rootCA Certificate, id int64, updateInterval time.Duration, revs []RevocationEntity) ([]byte, error) {
	if !rootCA.IsValidPair() {
		return nil, errors.New("invalid Root CA certificate")
	}

	if !rootCA.IsCA() {
		return nil, errors.New("invalid Root CA certificate: is not CA")
	}

	list := make([]x509.RevocationListEntry, 0, len(revs))
	for _, rev := range revs {
		list = append(list, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(rev.SerialNumber),
			RevocationTime: rev.RevocationTime,
		})
	}

	template := &x509.RevocationList{
		Number:                    big.NewInt(id),
		Issuer:                    rootCA.Crt.Subject,
		SignatureAlgorithm:        rootCA.Crt.SignatureAlgorithm,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(updateInterval),
		RevokedCertificateEntries: list,
	}

	b, err := x509.CreateRevocationList(rand.Reader, template, rootCA.Crt, rootCA.Key)
	if err != nil {
		return nil, fmt.Errorf("failed create revocation list: %w", err)
	}

	return b, nil
}

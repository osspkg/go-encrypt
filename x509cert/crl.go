/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package x509cert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

type RevocationEntity struct {
	SerialNumber   int64     `yaml:"serial_number" json:"serial_number"`
	RevocationTime time.Time `yaml:"revocation_time" json:"revocation_time"`
}

func NewCRL(ca Cert, serialNumber int64, updateInterval time.Duration, revs []RevocationEntity) (*RawCRL, error) {
	list := make([]x509.RevocationListEntry, 0, len(revs))
	for _, rev := range revs {
		list = append(list, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(rev.SerialNumber),
			RevocationTime: rev.RevocationTime,
		})
	}

	template := &x509.RevocationList{
		Number:                    big.NewInt(serialNumber),
		Issuer:                    ca.Cert.Certificate.Subject,
		SignatureAlgorithm:        ca.Cert.Certificate.SignatureAlgorithm,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(updateInterval),
		RevokedCertificateEntries: list,
		ExtraExtensions:           []pkix.Extension{},
	}

	b, err := x509.CreateRevocationList(rand.Reader, template, ca.Cert.Certificate, ca.Key.Key)
	if err != nil {
		return nil, fmt.Errorf("failed create revocation list: %w", err)
	}

	return &RawCRL{b}, nil
}

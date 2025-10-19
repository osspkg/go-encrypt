/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

func NewIntermediateCA(
	conf Config,
	rootCA Certificate,
	deadline time.Duration,
	serialNumber int64,
) (*Certificate, error) {

	currTime := time.Now()
	template := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    rootCA.Crt.SignatureAlgorithm,
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               conf.Subject(),
		NotBefore:             currTime,
		NotAfter:              currTime.Add(deadline),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		OCSPServer:            stringsPrepare(conf.OCSPServerURLs),
		IssuingCertificateURL: stringsPrepare(conf.IssuingCertificateURLs),
		CRLDistributionPoints: stringsPrepare(conf.CRLDistributionPointURLs),
		ExtraExtensions:       conf.ExtraExtensions(),
		EmailAddresses:        stringsPrepare(conf.EmailAddress),
		MaxPathLenZero:        false,
		MaxPathLen:            1,
	}

	if !rootCA.IsValidPair() {
		return nil, fmt.Errorf("invalid Root CA certificate")
	}

	if !rootCA.IsCA() {
		return nil, fmt.Errorf("invalid Root CA certificate: is not CA")
	}

	if rootCA.Crt.MaxPathLen != 2 {
		return nil, fmt.Errorf("invalid Root CA certificate: not supported Intermediate CA")
	}

	if template.NotAfter.After(rootCA.Crt.NotAfter) {
		return nil, fmt.Errorf("invalid Root CA certificate: NotAfter cannot be in the future")
	}

	algName, ok := signatures.Get(template.SignatureAlgorithm)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", template.SignatureAlgorithm.String())
	}

	alg, ok := algorithms.Get(algName)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", algName.String())
	}

	key, err := alg.Generate(InterCACert)
	if err != nil {
		return nil, fmt.Errorf("failed generating private key: %w", err)
	}

	b, err := x509.CreateCertificate(rand.Reader, template, rootCA.Crt, key.Public(), rootCA.Key)
	if err != nil {
		return nil, fmt.Errorf("failed generating certificate: %w", err)
	}

	cert, err := UnmarshalCrtDER(b)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificate: %w", err)
	}

	return &Certificate{Key: key, Crt: cert}, nil
}

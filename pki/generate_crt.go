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

func NewCRT(
	conf Config,
	rootCA Certificate,
	deadline time.Duration,
	serialNumber int64,
	domains ...string,
) (*Certificate, error) {
	if !rootCA.IsValidPair() {
		return nil, fmt.Errorf("invalid Root CA certificate")
	}

	if !rootCA.IsCA() {
		return nil, fmt.Errorf("invalid Root CA certificate: is not CA")
	}

	if rootCA.Crt.MaxPathLen != 1 {
		return nil, fmt.Errorf("invalid Root CA certificate: not supported generate client certificate")
	}

	currTime := time.Now()
	template := &x509.Certificate{
		IsCA:                  false,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    rootCA.Crt.SignatureAlgorithm,
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               conf.Subject(),
		NotBefore:             currTime,
		NotAfter:              currTime.Add(deadline),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		OCSPServer:            stringsPrepare(conf.OCSPServerURLs),
		IssuingCertificateURL: stringsPrepare(conf.IssuingCertificateURLs),
		CRLDistributionPoints: stringsPrepare(conf.CRLDistributionPointURLs),
		ExtraExtensions:       conf.ExtraExtensions(),
		EmailAddresses:        stringsPrepare(conf.EmailAddress),
	}

	if template.NotAfter.After(rootCA.Crt.NotAfter) {
		return nil, fmt.Errorf("invalid deadline: cannot be in the future then NotAfter Root CA certificate")
	}

	var err error
	template.IPAddresses, template.DNSNames, err = splitDomains(domains)
	if err != nil {
		return nil, fmt.Errorf("invalid domains: %w", err)
	}

	if len(template.DNSNames) > 0 {
		template.Subject.CommonName = template.DNSNames[0]
	} else if len(template.IPAddresses) > 0 {
		template.Subject.CommonName = template.IPAddresses[0].String()
	}

	algName, ok := signatures.Get(template.SignatureAlgorithm)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", template.SignatureAlgorithm.String())
	}

	alg, ok := algorithms.Get(algName)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", algName.String())
	}

	key, err := alg.Generate(ClientCert)
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

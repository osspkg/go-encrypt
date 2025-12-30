/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

func NewCSR(signatureAlgorithm x509.SignatureAlgorithm, domains ...string) (*Request, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("no certificate domains provided")
	}

	algName, ok := signatures.Get(signatureAlgorithm)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", signatureAlgorithm.String())
	}
	alg, ok := algorithms.Get(algName)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", algName.String())
	}

	template := &x509.CertificateRequest{
		SignatureAlgorithm: signatureAlgorithm,
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

	key, err := alg.Generate(template.SignatureAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed generating private key: %w", err)
	}

	b, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("failed creating certificate request: %w", err)
	}

	cert, err := UnmarshalCsrDER(b)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificate: %w", err)
	}

	return &Request{Key: key, Csr: cert}, nil
}

func SignCSR(
	conf Config,
	rootCA Certificate,
	csr x509.CertificateRequest,
	deadline time.Duration,
	serialNumber int64,
) (*x509.Certificate, error) {
	if !rootCA.IsValidPair() {
		return nil, fmt.Errorf("invalid Root CA certificate")
	}

	if !rootCA.IsCA() {
		return nil, fmt.Errorf("invalid Root CA certificate: is not CA")
	}

	if rootCA.Crt.MaxPathLen != 0 {
		return nil, fmt.Errorf("invalid Root CA certificate: not supported generate client certificate")
	}

	confSigAlg := conf.SignatureAlgorithm
	if confSigAlg == x509.UnknownSignatureAlgorithm {
		confSigAlg = rootCA.Crt.SignatureAlgorithm
	}

	if _, ok := signatures.Get(confSigAlg); !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", confSigAlg.String())
	}

	currTime := time.Now()
	template := &x509.Certificate{
		IsCA:                  false,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    confSigAlg,
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               csr.Subject,
		NotBefore:             currTime,
		NotAfter:              currTime.Add(deadline),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		OCSPServer:            stringsPrepare(conf.OCSPServerURLs),
		IssuingCertificateURL: stringsPrepare(conf.IssuingCertificateURLs),
		CRLDistributionPoints: stringsPrepare(conf.CRLDistributionPointURLs),
		//ExtraExtensions:       conf.extraExtensions(),
		DNSNames:    csr.DNSNames,
		IPAddresses: csr.IPAddresses,
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling public key: %w", err)
	}
	publicKeyHash := sha256.Sum256(publicKeyBytes)
	template.SubjectKeyId = publicKeyHash[:20]

	b, err := x509.CreateCertificate(rand.Reader, template, rootCA.Crt, csr.PublicKey, rootCA.Key)
	if err != nil {
		return nil, fmt.Errorf("failed generating certificate: %w", err)
	}

	cert, err := UnmarshalCrtDER(b)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificate: %w", err)
	}

	return cert, nil
}

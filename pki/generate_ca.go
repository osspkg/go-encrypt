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

func NewCA(
	conf Config,
	deadline time.Duration,
	serialNumber int64,
	intermediateCount int,
) (*Certificate, error) {
	intermediateCount = max(0, intermediateCount)

	currTime := time.Now()
	template := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    conf.SignatureAlgorithm,
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               conf.Subject(),
		NotBefore:             currTime,
		NotAfter:              currTime.Add(deadline),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		OCSPServer:            stringsPrepare(conf.OCSPServerURLs),
		IssuingCertificateURL: stringsPrepare(conf.IssuingCertificateURLs),
		CRLDistributionPoints: stringsPrepare(conf.CRLDistributionPointURLs),
		//ExtraExtensions:       conf.extraExtensions(),
		MaxPathLen:     intermediateCount,
		MaxPathLenZero: intermediateCount <= 0,
	}

	algName, ok := signatures.Get(template.SignatureAlgorithm)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", template.SignatureAlgorithm.String())
	}

	alg, ok := algorithms.Get(algName)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", algName.String())
	}

	key, err := alg.Generate(template.SignatureAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed generating private key: %w", err)
	}

	//publicKeyBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	//if err != nil {
	//	return nil, fmt.Errorf("failed marshaling public key: %w", err)
	//}
	//publicKeyHash := sha256.Sum256(publicKeyBytes)
	//template.SubjectKeyId = publicKeyHash[:20]
	//template.AuthorityKeyId = publicKeyHash[:20]

	b, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("failed generating certificate: %w", err)
	}

	cert, err := UnmarshalCrtDER(b)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificate: %w", err)
	}

	return &Certificate{Key: key, Crt: cert}, nil
}

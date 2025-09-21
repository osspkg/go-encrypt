/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package x509cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"time"

	"go.osspkg.com/errors"
)

func NewCA(c Config, ca *Cert, bits int, deadline time.Duration, serialNumber int64, commonName string) (Cert,
	error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return Cert{}, errors.Wrapf(err, "generate private key")
	}

	template := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    c.SignatureAlgorithm,
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               c.ToSubject(),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(deadline),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		OCSPServer:            c.OCSPServer,
		IssuingCertificateURL: c.IssuingCertificateURL,
		CRLDistributionPoints: c.CRLDistributionPoints,
	}
	template.Subject.CommonName = commonName

	var crt []byte
	if ca != nil && !ca.IsEmpty() {
		template.MaxPathLenZero = false
		template.MaxPathLen = ca.Cert.Certificate.MaxPathLen + 1

		if template.NotAfter.After(ca.Cert.Certificate.NotAfter) {
			return Cert{}, errors.New("deadline expires after root certificate expires")
		}

		crt, err = x509.CreateCertificate(rand.Reader, template, ca.Cert.Certificate, &key.PublicKey, ca.Key.Key)
	} else {
		template.MaxPathLenZero = true
		template.MaxPathLen = 0

		crt, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	}
	if err != nil {
		return Cert{}, errors.Wrapf(err, "create certificate")
	}

	rc := &RawCert{}
	if err = rc.DecodeDER(crt); err != nil {
		return Cert{}, errors.Wrapf(err, "decode certificate")
	}

	return Cert{
		Cert: rc,
		Key:  &RawKey{Key: key},
	}, nil
}

func NewCert(c Config, ca Cert, bits int, deadline time.Duration, serialNumber int64, commonNames ...string) (Cert, error) {
	if ca.IsEmpty() {
		return Cert{}, errors.New("CA cert is empty")
	}
	ok, err := ca.Cert.IsCa()
	if err != nil {
		return Cert{}, err
	}
	if !ok {
		return Cert{}, errors.New("CA cert is not valid")
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return Cert{}, errors.Wrapf(err, "generate private key")
	}

	template := &x509.Certificate{
		IsCA:                  false,
		BasicConstraintsValid: false,
		SignatureAlgorithm:    c.SignatureAlgorithm,
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               c.ToSubject(),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(deadline),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		OCSPServer:            c.OCSPServer,
		IssuingCertificateURL: c.IssuingCertificateURL,
		CRLDistributionPoints: c.CRLDistributionPoints,
	}

	if template.NotAfter.After(ca.Cert.Certificate.NotAfter) {
		return Cert{}, errors.New("deadline expires after root certificate expires")
	}

	commonName := "*"
	ips, dns, err := splitCommonNames(commonNames)
	if err != nil {
		return Cert{}, errors.Wrapf(err, "apply common names")
	}
	if len(dns) > 0 {
		commonName = dns[0]
	}
	template.Subject.CommonName = commonName
	template.IPAddresses = ips
	template.DNSNames = dns

	crt, err := x509.CreateCertificate(rand.Reader, template, ca.Cert.Certificate, &key.PublicKey, ca.Key.Key)
	if err != nil {
		return Cert{}, errors.Wrapf(err, "create certificate")
	}

	rc := &RawCert{}
	if err = rc.DecodeDER(crt); err != nil {
		return Cert{}, errors.Wrapf(err, "decode certificate")
	}

	return Cert{
		Cert: rc,
		Key:  &RawKey{Key: key},
	}, nil
}

/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"crypto"
	"crypto/x509"

	"go.osspkg.com/syncing"
)

var (
	signatures = syncing.NewMap[x509.SignatureAlgorithm, x509.PublicKeyAlgorithm](5)
	algorithms = syncing.NewMap[x509.PublicKeyAlgorithm, Algorithm](5)
)

func Register(k x509.SignatureAlgorithm, v Algorithm) {
	signatures.Set(k, v.Name())
	algorithms.Set(v.Name(), v)
}

func init() {
	Register(x509.SHA256WithRSA, &_rsa{})
	Register(x509.SHA384WithRSA, &_rsa{})
	Register(x509.SHA512WithRSA, &_rsa{})
	Register(x509.ECDSAWithSHA256, &_ecdsa{})
	Register(x509.ECDSAWithSHA384, &_ecdsa{})
	Register(x509.ECDSAWithSHA512, &_ecdsa{})
}

type Algorithm interface {
	Name() x509.PublicKeyAlgorithm
	IsPrivateKey(key crypto.Signer) bool
	IsRequest(cert x509.CertificateRequest) bool
	IsCertificate(cert x509.Certificate) bool
	IsValidPair(key crypto.Signer, cert x509.Certificate) bool
	Generate(ct CertType) (crypto.Signer, error)
}

type CertType string

const (
	RootCaCert  CertType = "root_ca_cert"
	InterCACert CertType = "intermediate_ca_cert"
	ClientCert  CertType = "client_cert"
)

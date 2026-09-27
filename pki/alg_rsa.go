/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"reflect"
)

type _rsa struct{}

// Name returns the public-key algorithm supported by this implementation.
func (*_rsa) Name() x509.PublicKeyAlgorithm {
	return x509.RSA
}

// IsPrivateKey reports whether key is a private key supported by this implementation.
func (*_rsa) IsPrivateKey(key crypto.Signer) bool {
	_, ok := key.(*rsa.PrivateKey)
	return ok
}

// IsCertificate reports whether cert uses a public-key algorithm supported by this implementation.
func (*_rsa) IsCertificate(cert x509.Certificate) bool {
	_, ok := cert.PublicKey.(*rsa.PublicKey)
	return ok
}

// IsRequest reports whether cert uses a public-key algorithm supported by this implementation.
func (*_rsa) IsRequest(cert x509.CertificateRequest) bool {
	_, ok := cert.PublicKey.(*rsa.PublicKey)
	return ok
}

// IsValidPair reports whether key matches the certificate public key.
func (*_rsa) IsValidPair(key crypto.Signer, cert x509.Certificate) bool {
	raw, ok := key.(*rsa.PrivateKey)
	if !ok {
		return false
	}
	pk, ok := raw.Public().(*rsa.PublicKey)
	if !ok {
		return false
	}
	ck, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}

	return reflect.DeepEqual(pk, ck)
}

// Generate generates a private key for the requested signature algorithm.
func (*_rsa) Generate(alg x509.SignatureAlgorithm) (crypto.Signer, error) {
	var bits int
	switch alg {
	case x509.SHA512WithRSA, x509.SHA384WithRSA,
		x509.SHA512WithRSAPSS, x509.SHA384WithRSAPSS:
		bits = 4096
	case x509.SHA256WithRSA:
		bits = 3072
	default:
		return nil, fmt.Errorf("unknown certificate bits for '%s'", alg.String())
	}

	return rsa.GenerateKey(rand.Reader, bits)
}

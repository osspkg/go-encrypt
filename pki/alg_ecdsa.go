/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

// Package pki creates and encodes X.509 certificates, keys, and revocation data.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"reflect"
)

type _ecdsa struct{}

// Name returns the public-key algorithm supported by this implementation.
func (*_ecdsa) Name() x509.PublicKeyAlgorithm {
	return x509.ECDSA
}

// IsPrivateKey reports whether key is a private key supported by this implementation.
func (*_ecdsa) IsPrivateKey(key crypto.Signer) bool {
	_, ok := key.(*ecdsa.PrivateKey)
	return ok
}

// IsCertificate reports whether cert uses a public-key algorithm supported by this implementation.
func (*_ecdsa) IsCertificate(cert x509.Certificate) bool {
	_, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok
}

// IsRequest reports whether cert uses a public-key algorithm supported by this implementation.
func (*_ecdsa) IsRequest(cert x509.CertificateRequest) bool {
	_, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok
}

// IsValidPair reports whether key matches the certificate public key.
func (*_ecdsa) IsValidPair(key crypto.Signer, cert x509.Certificate) bool {
	raw, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return false
	}
	pk, ok := raw.Public().(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	ck, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	return reflect.DeepEqual(pk, ck)
}

// Generate generates a private key for the requested signature algorithm.
func (*_ecdsa) Generate(alg x509.SignatureAlgorithm) (crypto.Signer, error) {
	var curve elliptic.Curve
	switch alg {
	case x509.ECDSAWithSHA256:
		curve = elliptic.P256()
	case x509.ECDSAWithSHA384:
		curve = elliptic.P384()
	case x509.ECDSAWithSHA512:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unknown certificate curve for '%s'", alg.String())
	}

	return ecdsa.GenerateKey(curve, rand.Reader)
}

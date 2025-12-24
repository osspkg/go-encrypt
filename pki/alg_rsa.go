/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
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

func (*_rsa) Name() x509.PublicKeyAlgorithm {
	return x509.RSA
}

func (*_rsa) IsPrivateKey(key crypto.Signer) bool {
	_, ok := key.(*rsa.PrivateKey)
	return ok
}

func (*_rsa) IsCertificate(cert x509.Certificate) bool {
	_, ok := cert.PublicKey.(*rsa.PublicKey)
	return ok
}

func (*_rsa) IsRequest(cert x509.CertificateRequest) bool {
	_, ok := cert.PublicKey.(*rsa.PublicKey)
	return ok
}

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

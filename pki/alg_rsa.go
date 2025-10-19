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

func (*_rsa) Generate(ct CertType) (crypto.Signer, error) {
	var bits int
	switch ct {
	case RootCaCert:
		bits = 4096
	case InterCACert:
		bits = 3072
	case ClientCert:
		bits = 2048
	default:
		return nil, fmt.Errorf("unknown certificate bits for '%s'", ct)
	}

	return rsa.GenerateKey(rand.Reader, bits)
}

/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

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

func (*_ecdsa) Name() x509.PublicKeyAlgorithm {
	return x509.ECDSA
}

func (*_ecdsa) IsPrivateKey(key crypto.Signer) bool {
	_, ok := key.(*ecdsa.PrivateKey)
	return ok
}

func (*_ecdsa) IsCertificate(cert x509.Certificate) bool {
	_, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok
}

func (*_ecdsa) IsRequest(cert x509.CertificateRequest) bool {
	_, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok
}

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

func (*_ecdsa) Generate(ct CertType) (crypto.Signer, error) {
	var curve elliptic.Curve
	switch ct {
	case RootCaCert:
		curve = elliptic.P256()
	case InterCACert:
		curve = elliptic.P384()
	case ClientCert:
		curve = elliptic.P256()
	default:
		return nil, fmt.Errorf("unknown certificate curve for '%s'", ct)
	}

	return ecdsa.GenerateKey(curve, rand.Reader)
}

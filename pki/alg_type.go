/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"go.osspkg.com/syncing"
)

const initialAlgorithmCapacity = 5

var (
	signatures = syncing.NewMap[x509.SignatureAlgorithm, x509.PublicKeyAlgorithm](initialAlgorithmCapacity)
	algorithms = syncing.NewMap[x509.PublicKeyAlgorithm, Algorithm](initialAlgorithmCapacity)
)

// Register associates a signature algorithm with a key implementation.
// Registration affects subsequent certificate and request generation. Register
// custom algorithms before starting operations that use them.
func Register(k x509.SignatureAlgorithm, v Algorithm) {
	signatures.Set(k, v.Name())
	algorithms.Set(v.Name(), v)
}

func init() {
	Register(x509.SHA256WithRSA, &_rsa{})
	Register(x509.SHA256WithRSAPSS, &_rsa{})
	Register(x509.SHA384WithRSA, &_rsa{})
	Register(x509.SHA384WithRSAPSS, &_rsa{})
	Register(x509.SHA512WithRSA, &_rsa{})
	Register(x509.SHA512WithRSAPSS, &_rsa{})
	Register(x509.ECDSAWithSHA256, &_ecdsa{})
	Register(x509.ECDSAWithSHA384, &_ecdsa{})
	Register(x509.ECDSAWithSHA512, &_ecdsa{})
}

// Algorithm generates and validates keys supported by the certificate package.
type Algorithm interface {
	// Name returns the public-key algorithm handled by the implementation.
	Name() x509.PublicKeyAlgorithm
	// IsPrivateKey reports whether key is a private key handled by the implementation.
	IsPrivateKey(key crypto.Signer) bool
	// IsRequest reports whether the request public key is handled by the implementation.
	IsRequest(cert x509.CertificateRequest) bool
	// IsCertificate reports whether the certificate public key is handled by the implementation.
	IsCertificate(cert x509.Certificate) bool
	// IsValidPair reports whether key corresponds to cert's public key.
	IsValidPair(key crypto.Signer, cert x509.Certificate) bool
	// Generate creates a private key suitable for alg or returns an error if alg
	// is not supported.
	Generate(alg x509.SignatureAlgorithm) (crypto.Signer, error)
}

func algorithmForSignature(signatureAlgorithm x509.SignatureAlgorithm) (Algorithm, error) {
	algorithmName, ok := signatures.Get(signatureAlgorithm)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", signatureAlgorithm.String())
	}
	algorithm, ok := algorithms.Get(algorithmName)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", algorithmName.String())
	}
	return algorithm, nil
}

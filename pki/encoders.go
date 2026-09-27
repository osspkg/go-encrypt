/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

var pemEndLine = []byte("\n-----END ")

// TypePEMBlock identifies the PEM block type used by an encoder.
type TypePEMBlock string

const (
	// CertificatePEMBlock is the PEM type label for an X.509 certificate.
	CertificatePEMBlock TypePEMBlock = "CERTIFICATE"
	// PrivateKeyPEMBlock is the PEM type label for PKCS #8 private keys.
	PrivateKeyPEMBlock TypePEMBlock = "PRIVATE KEY"
	// RevocationListPEMBlock is the PEM type label for a certificate revocation list.
	RevocationListPEMBlock TypePEMBlock = "X509 CRL"
	// CertificateRequestPEMBlock is the PEM label for an X.509 certificate request.
	CertificateRequestPEMBlock TypePEMBlock = "CERTIFICATE REQUEST"
)

// CreatePEMBlock encodes bytes in a PEM block with the requested type and prefix.
func CreatePEMBlock(b []byte, t TypePEMBlock, prefix string) []byte {
	s := string(t)
	if len(prefix) > 0 {
		s = prefix + " " + s
	}

	block := &pem.Block{Type: s, Bytes: b}

	return pem.EncodeToMemory(block)
}

// ---------------------------------------------------------------------------------------------------------------------

// MarshalKeyDER encodes a private key as PKCS #8 DER.
func MarshalKeyDER(key crypto.Signer) ([]byte, error) {
	if key == nil {
		return nil, errors.New("no private key provided")
	}

	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8 private key: %w", err)
	}

	return b, nil
}

// UnmarshalKeyDER parses a PKCS #8 DER private key.
func UnmarshalKeyDER(b []byte) (crypto.Signer, error) {
	if len(b) == 0 {
		return nil, errors.New("no private key provided")
	}

	raw, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PKCS#8 private key: %w", err)
	}

	key, ok := raw.(crypto.Signer)
	if !ok {
		return nil, errors.New("PKCS#8 private key does not implement crypto.Signer")
	}

	return key, nil
}

// MarshalCrtDER returns the certificate DER bytes.
func MarshalCrtDER(cert x509.Certificate) []byte {
	return cert.Raw
}

// UnmarshalCrtDER parses a DER encoded X.509 certificate.
func UnmarshalCrtDER(b []byte) (*x509.Certificate, error) {
	if len(b) == 0 {
		return nil, errors.New("no certificate provided")
	}

	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PKCS#8 certificate: %w", err)
	}

	return cert, nil
}

// MarshalKeyPEM encodes a private key as PKCS #8 PEM.
func MarshalKeyPEM(key crypto.Signer) ([]byte, error) {
	b, err := MarshalKeyDER(key)
	if err != nil {
		return nil, err
	}

	var prefix string
	// for name, a := range algorithms.Yield() {
	//	if !a.IsPrivateKey(key) {
	//		continue
	//	}
	//	prefix = name.String()
	//}

	return CreatePEMBlock(b, PrivateKeyPEMBlock, prefix), nil
}

// UnmarshalKeyPEM parses a PKCS #8 PEM private key.
func UnmarshalKeyPEM(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil || !strings.HasSuffix(block.Type, string(PrivateKeyPEMBlock)) {
		return nil, errors.New("no private key provided")
	}
	return UnmarshalKeyDER(block.Bytes)
}

// MarshalCrtPEM encodes an X.509 certificate as PEM.
func MarshalCrtPEM(cert x509.Certificate) ([]byte, error) {
	b := MarshalCrtDER(cert)

	return CreatePEMBlock(b, CertificatePEMBlock, ""), nil
}

// UnmarshalCrtPEM parses a PEM encoded X.509 certificate.
func UnmarshalCrtPEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil || !strings.HasSuffix(block.Type, string(CertificatePEMBlock)) {
		return nil, errors.New("no certificate provided")
	}
	return UnmarshalCrtDER(block.Bytes)
}

// MarshalCsrDER returns the certificate request DER bytes.
func MarshalCsrDER(cert x509.CertificateRequest) []byte {
	return cert.Raw
}

// UnmarshalCsrDER parses a DER encoded certificate request.
func UnmarshalCsrDER(b []byte) (*x509.CertificateRequest, error) {
	if len(b) == 0 {
		return nil, errors.New("no CSR provided")
	}
	cert, err := x509.ParseCertificateRequest(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PKCS#8 request: %w", err)
	}
	return cert, nil
}

// MarshalCsrPEM encodes a certificate request as PEM.
func MarshalCsrPEM(cert x509.CertificateRequest) ([]byte, error) {
	b := MarshalCsrDER(cert)

	return CreatePEMBlock(b, CertificateRequestPEMBlock, ""), nil
}

// UnmarshalCsrPEM parses a PEM encoded certificate request.
func UnmarshalCsrPEM(b []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(b)
	if block == nil || !strings.HasSuffix(block.Type, string(CertificateRequestPEMBlock)) {
		return nil, errors.New("no certificate provided")
	}
	return UnmarshalCsrDER(block.Bytes)
}

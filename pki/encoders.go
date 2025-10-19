/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

var pemEndLine = []byte("\n-----END ")

type TypePEMBlock string

const (
	CertificatePEMBlock        TypePEMBlock = "CERTIFICATE"
	PrivateKeyPEMBlock         TypePEMBlock = "PRIVATE KEY"
	RevocationListPEMBlock     TypePEMBlock = "X509 CRL"
	CertificateRequestPEMBlock TypePEMBlock = "CERTIFICATE REQUEST"
)

func CreatePEMBlock(b []byte, t TypePEMBlock, prefix string) []byte {
	s := string(t)
	if len(prefix) > 0 {
		s = prefix + " " + s
	}

	block := &pem.Block{Type: s, Bytes: b}

	return pem.EncodeToMemory(block)
}

// ---------------------------------------------------------------------------------------------------------------------

func MarshalKeyDER(key crypto.Signer) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("no private key provided")
	}

	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8 private key: %w", err)
	}

	return b, nil
}

func UnmarshalKeyDER(b []byte) (crypto.Signer, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("no private key provided")
	}

	raw, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PKCS#8 private key: %w", err)
	}

	key, ok := raw.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 private key does not implement crypto.Signer")
	}

	return key, nil
}

func MarshalCrtDER(cert x509.Certificate) []byte {
	return cert.Raw
}

func UnmarshalCrtDER(b []byte) (*x509.Certificate, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("no certificate provided")
	}

	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PKCS#8 certificate: %w", err)
	}

	return cert, nil
}

func MarshalKeyPEM(key crypto.Signer) ([]byte, error) {
	b, err := MarshalKeyDER(key)
	if err != nil {
		return nil, err
	}

	var prefix string
	for name, a := range algorithms.Yield() {
		if !a.IsPrivateKey(key) {
			continue
		}

		prefix = name.String()
	}

	return CreatePEMBlock(b, PrivateKeyPEMBlock, prefix), nil
}

func UnmarshalKeyPEM(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil || !strings.HasSuffix(block.Type, string(PrivateKeyPEMBlock)) {
		return nil, fmt.Errorf("no private key provided")
	}
	return UnmarshalKeyDER(block.Bytes)
}

func MarshalCrtPEM(cert x509.Certificate) ([]byte, error) {
	b := MarshalCrtDER(cert)

	return CreatePEMBlock(b, CertificatePEMBlock, ""), nil
}

func UnmarshalCrtPEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil || !strings.HasSuffix(block.Type, string(CertificatePEMBlock)) {
		return nil, fmt.Errorf("no certificate provided")
	}
	return UnmarshalCrtDER(block.Bytes)
}

func MarshalCsrDER(cert x509.CertificateRequest) []byte {
	return cert.Raw
}

func UnmarshalCsrDER(b []byte) (*x509.CertificateRequest, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("no CSR provided")
	}
	cert, err := x509.ParseCertificateRequest(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PKCS#8 request: %w", err)
	}
	return cert, nil
}

func MarshalCsrPEM(cert x509.CertificateRequest) ([]byte, error) {
	b := MarshalCsrDER(cert)

	return CreatePEMBlock(b, CertificateRequestPEMBlock, ""), nil
}

func UnmarshalCsrPEM(b []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(b)
	if block == nil || !strings.HasSuffix(block.Type, string(CertificateRequestPEMBlock)) {
		return nil, fmt.Errorf("no certificate provided")
	}
	return UnmarshalCsrDER(block.Bytes)
}

/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package x509cert

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
)

var (
	ErrDecodePEMBlock       = errors.New("crypto/x509: failed decoding PEM block")
	ErrEmptyCertificate     = errors.New("certificate is nil")
	ErrNotInitedCertificate = errors.New("certificate is not initialized")
	ErrEmptyKey             = errors.New("key is nil")
	ErrNotInitedKey         = errors.New("key is not initialized")
	ErrHashAlgNotDefined    = errors.New("hash algorithm not defined")
)

type RawCert struct {
	Certificate *x509.Certificate
}

func (v *RawCert) IsCa() (bool, error) {
	if v == nil || v.Certificate == nil {
		return false, ErrEmptyCertificate
	}

	return v.Certificate.IsCA, nil
}

func (v *RawCert) FingerPrint(h crypto.Hash) ([]byte, error) {
	if v == nil || v.Certificate == nil {
		return nil, ErrEmptyCertificate
	}

	if !h.Available() {
		return nil, ErrHashAlgNotDefined
	}

	w := h.New()
	w.Write(v.Certificate.Raw)

	return w.Sum(nil), nil
}

func (v *RawCert) IssuerKeyHash(h crypto.Hash) ([]byte, error) {
	if v == nil || v.Certificate == nil {
		return nil, ErrEmptyCertificate
	}

	if !h.Available() {
		return nil, ErrHashAlgNotDefined
	}

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	if _, err := asn1.Unmarshal(v.Certificate.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, err
	}

	w := h.New()
	w.Write(publicKeyInfo.PublicKey.RightAlign())

	return w.Sum(nil), nil
}

func (v *RawCert) IssuerNameHash(h crypto.Hash) ([]byte, error) {
	if v == nil || v.Certificate == nil {
		return nil, ErrEmptyCertificate
	}

	if !h.Available() {
		return nil, ErrHashAlgNotDefined
	}

	w := h.New()
	w.Write(v.Certificate.RawSubject)

	return w.Sum(nil), nil
}

func (v *RawCert) EncodeDER() ([]byte, error) {
	if v == nil || v.Certificate == nil {
		return nil, ErrEmptyCertificate
	}
	return v.Certificate.Raw, nil
}

func (v *RawCert) EncodePEM() ([]byte, error) {
	b, err := v.EncodeDER()
	if err != nil {
		return nil, err
	}
	return encodePEM(b, pemTypeCertificate), nil
}

func (v *RawCert) EncodeDERFile(filename string) error {
	b, err := v.EncodeDER()
	if err != nil {
		return err
	}

	return os.WriteFile(filename, b, 0644)
}

func (v *RawCert) EncodePEMFile(filename string) error {
	b, err := v.EncodePEM()
	if err != nil {
		return err
	}

	return os.WriteFile(filename, b, 0644)
}

func (v *RawCert) DecodeDER(b []byte) (err error) {
	if v == nil {
		return ErrNotInitedCertificate
	}
	v.Certificate, err = x509.ParseCertificate(b)
	return
}

func (v *RawCert) DecodePEM(b []byte) error {
	if v == nil {
		return ErrNotInitedCertificate
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != string(pemTypeCertificate) {
		return ErrDecodePEMBlock
	}
	return v.DecodeDER(block.Bytes)
}

func (v *RawCert) DecodeDERFile(filename string) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return v.DecodeDER(b)
}

func (v *RawCert) DecodePEMFile(filename string) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return v.DecodePEM(b)
}

// -------------------------------------------------------------------------------------------------------------------

type RawKey struct {
	Key *rsa.PrivateKey
}

func (v *RawKey) EncodeDER() ([]byte, error) {
	if v == nil || v.Key == nil {
		return nil, ErrEmptyKey
	}
	return x509.MarshalPKCS1PrivateKey(v.Key), nil
}

func (v *RawKey) EncodePEM() ([]byte, error) {
	b, err := v.EncodeDER()
	if err != nil {
		return nil, err
	}
	return encodePEM(b, pemTypePrivateKey), nil
}

func (v *RawKey) EncodeDERFile(filename string) error {
	b, err := v.EncodeDER()
	if err != nil {
		return err
	}

	return os.WriteFile(filename, b, 0600)
}

func (v *RawKey) EncodePEMFile(filename string) error {
	b, err := v.EncodePEM()
	if err != nil {
		return err
	}

	return os.WriteFile(filename, b, 0600)
}

func (v *RawKey) DecodeDER(b []byte) (err error) {
	if v == nil {
		return ErrNotInitedKey
	}
	v.Key, err = x509.ParsePKCS1PrivateKey(b)
	return
}

func (v *RawKey) DecodePEM(b []byte) error {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != string(pemTypePrivateKey) {
		return ErrDecodePEMBlock
	}
	return v.DecodeDER(block.Bytes)
}

func (v *RawKey) DecodeDERFile(filename string) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return v.DecodeDER(b)
}

func (v *RawKey) DecodePEMFile(filename string) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return v.DecodePEM(b)
}

// -------------------------------------------------------------------------------------------------------------------

type RawCRL struct {
	b []byte
}

func (v *RawCRL) EncodeDER() []byte {
	if v == nil {
		return nil
	}
	return v.b
}

func (v *RawCRL) EncodePEM() []byte {
	if v == nil {
		return nil
	}
	return encodePEM(v.b, pemTypeRevocationList)
}

func (v *RawCRL) EncodeDERFile(filename string) error {
	if v == nil {
		return nil
	}
	return os.WriteFile(filename, v.EncodeDER(), 0744)
}

func (v *RawCRL) EncodePEMFile(filename string) error {
	if v == nil {
		return nil
	}
	return os.WriteFile(filename, v.EncodePEM(), 0744)
}

// -------------------------------------------------------------------------------------------------------------------

type Cert struct {
	Cert *RawCert
	Key  *RawKey
}

func (c Cert) IsEmpty() bool {
	return c.Cert == nil || c.Cert.Certificate == nil ||
		c.Key == nil || c.Key.Key == nil
}

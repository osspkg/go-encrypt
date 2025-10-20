/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"os"
)

type Certificate struct {
	Key crypto.Signer
	Crt *x509.Certificate
}

func (c *Certificate) IsValidPair() bool {
	if c == nil || c.Key == nil || c.Crt == nil {
		return false
	}

	for _, a := range algorithms.Yield() {
		if !a.IsPrivateKey(c.Key) {
			continue
		}
		return a.IsValidPair(c.Key, *c.Crt)
	}

	return false
}

func (c *Certificate) IsCA() bool {
	if c == nil || c.Crt == nil {
		return false
	}
	return c.Crt.IsCA
}

func (c *Certificate) FingerPrint(h crypto.Hash) ([]byte, error) {
	if c == nil || c.Crt == nil {
		return nil, fmt.Errorf("no certificate provided")
	}

	if !h.Available() {
		return nil, fmt.Errorf("hash algorithm not defined")
	}

	w := h.New()
	w.Write(c.Crt.Raw)

	return w.Sum(nil), nil
}

func (c *Certificate) IssuerKeyHash(h crypto.Hash) ([]byte, error) {
	if c == nil || c.Crt == nil {
		return nil, fmt.Errorf("no certificate provided")
	}

	if !h.Available() {
		return nil, fmt.Errorf("hash algorithm not defined")
	}

	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	if _, err := asn1.Unmarshal(c.Crt.RawSubjectPublicKeyInfo, &info); err != nil {
		return nil, err
	}

	w := h.New()
	w.Write(info.PublicKey.RightAlign())

	return w.Sum(nil), nil
}

func (c *Certificate) IssuerNameHash(h crypto.Hash) ([]byte, error) {
	if c == nil || c.Crt == nil {
		return nil, fmt.Errorf("no certificate provided")
	}

	if !h.Available() {
		return nil, fmt.Errorf("hash algorithm not defined")
	}

	w := h.New()
	w.Write(c.Crt.RawSubject)

	return w.Sum(nil), nil
}

func (c *Certificate) SaveKey(filepath string) error {
	if c == nil || c.Key == nil {
		return fmt.Errorf("no private key provided")
	}
	b, err := MarshalKeyPEM(c.Key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	err = os.WriteFile(filepath, b, 0600)
	if err != nil {
		return fmt.Errorf("save key to '%s': %w", filepath, err)
	}
	return nil
}

func (c *Certificate) SaveCert(filepath string) error {
	if c == nil || c.Crt == nil {
		return fmt.Errorf("no certificate provided")
	}
	b, err := MarshalCrtPEM(*c.Crt)
	if err != nil {
		return fmt.Errorf("marshal certificate: %w", err)
	}
	err = os.WriteFile(filepath, b, 0644)
	if err != nil {
		return fmt.Errorf("save certificate to '%s': %w", filepath, err)
	}
	return nil
}

func (c *Certificate) LoadKey(filepath string) error {
	b, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("load private key from '%s': %w", filepath, err)
	}
	if bytes.Contains(b, pemEndLine) {
		c.Key, err = UnmarshalKeyPEM(b)
	} else {
		c.Key, err = UnmarshalKeyDER(b)
	}
	return err
}

func (c *Certificate) LoadCert(filepath string) error {
	b, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("load certificate from '%s': %w", filepath, err)
	}
	if bytes.Contains(b, pemEndLine) {
		c.Crt, err = UnmarshalCrtPEM(b)
	} else {
		c.Crt, err = UnmarshalCrtDER(b)
	}
	return err
}

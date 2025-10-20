/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
)

type Request struct {
	Key crypto.Signer
	Csr *x509.CertificateRequest
}

func (c *Request) SaveKey(filepath string) error {
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

func (c *Request) SaveCert(filepath string) error {
	if c == nil || c.Csr == nil {
		return fmt.Errorf("no certificate request provided")
	}
	b, err := MarshalCsrPEM(*c.Csr)
	if err != nil {
		return fmt.Errorf("marshal certificate request: %w", err)
	}
	err = os.WriteFile(filepath, b, 0644)
	if err != nil {
		return fmt.Errorf("save certificate request to '%s': %w", filepath, err)
	}
	return nil
}

func (c *Request) LoadKey(filepath string) error {
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

func (c *Request) LoadCert(filepath string) error {
	b, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("load certificate request from '%s': %w", filepath, err)
	}
	if bytes.Contains(b, pemEndLine) {
		c.Csr, err = UnmarshalCsrPEM(b)
	} else {
		c.Csr, err = UnmarshalCsrDER(b)
	}
	return err
}

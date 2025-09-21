/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package x509cert

import (
	"encoding/pem"
	"fmt"
	"net"
)

func splitCommonNames(commonNames []string) ([]net.IP, []string, error) {
	if len(commonNames) == 0 {
		return nil, nil, fmt.Errorf("no common names specified")
	}

	ips := make([]net.IP, 0, len(commonNames))
	domains := make([]string, 0, len(commonNames))

	for _, commonName := range commonNames {
		if ip, _, err := net.SplitHostPort(commonName); err == nil {
			ips = append(ips, net.ParseIP(ip))
			continue
		}

		domains = append(domains, commonName)
	}

	return ips, domains, nil
}

type pemType string

const (
	pemTypeCertificate    pemType = "CERTIFICATE"
	pemTypePrivateKey     pemType = "RSA PRIVATE KEY"
	pemTypeRevocationList pemType = "X509 CRL"
)

func encodePEM(b []byte, t pemType) []byte {
	block := &pem.Block{
		Type:  string(t),
		Bytes: b,
	}

	return pem.EncodeToMemory(block)
}

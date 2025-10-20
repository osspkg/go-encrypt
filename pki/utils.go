/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"fmt"
	"net"
	"strings"
)

func splitDomains(commonNames []string) ([]net.IP, []string, error) {
	if len(commonNames) == 0 {
		return nil, nil, fmt.Errorf("domains is empty")
	}

	ips := make([]net.IP, 0, len(commonNames))
	domains := make([]string, 0, len(commonNames))

	for _, commonName := range stringsPrepare(commonNames) {
		if ip, _, err := net.SplitHostPort(commonName); err == nil {
			ips = append(ips, net.ParseIP(ip))
			continue
		}

		domains = append(domains, strings.TrimSpace(strings.ToLower(commonName)))
	}

	return ips, domains, nil
}

func stringsPrepare(list []string) (out []string) {
	for _, s := range list {
		s = strings.TrimSpace(s)
		if len(s) == 0 {
			continue
		}
		out = append(out, strings.ToLower(s))
	}
	return
}

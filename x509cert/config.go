/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package x509cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

type Config struct {
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	StreetAddress      string
	PostalCode         string

	OCSPServer            []string
	IssuingCertificateURL []string
	CRLDistributionPoints []string
	SignatureAlgorithm    x509.SignatureAlgorithm
}

func (v Config) ToSubject() pkix.Name {
	result := pkix.Name{}

	if len(v.Country) > 0 {
		result.Country = []string{v.Country}
	}
	if len(v.Organization) > 0 {
		result.Organization = []string{v.Organization}
	}
	if len(v.OrganizationalUnit) > 0 {
		result.OrganizationalUnit = []string{v.OrganizationalUnit}
	}
	if len(v.Locality) > 0 {
		result.Locality = []string{v.Locality}
	}
	if len(v.Province) > 0 {
		result.Province = []string{v.Province}
	}
	if len(v.StreetAddress) > 0 {
		result.StreetAddress = []string{v.StreetAddress}
	}
	if len(v.PostalCode) > 0 {
		result.PostalCode = []string{v.PostalCode}
	}

	return result
}

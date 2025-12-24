/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

type Config struct {
	SignatureAlgorithm x509.SignatureAlgorithm `yaml:"signature_algorithm" json:"signature_algorithm"`

	Organization       string `yaml:"organization,omitempty" json:"organization,omitempty"`
	OrganizationalUnit string `yaml:"organizational_unit,omitempty" json:"organizational_unit,omitempty"`
	Country            string `yaml:"country,omitempty" json:"country,omitempty"`
	Province           string `yaml:"province,omitempty" json:"province,omitempty"`
	Locality           string `yaml:"locality,omitempty" json:"locality,omitempty"`
	StreetAddress      string `yaml:"street_address,omitempty" json:"street_address,omitempty"`
	PostalCode         string `yaml:"postal_code,omitempty" json:"postal_code,omitempty"`
	CommonName         string `yaml:"common_name,omitempty" json:"common_name,omitempty"`

	OCSPServerURLs           []string `yaml:"ocsp_server_ur_ls,omitempty" json:"ocsp_server_ur_ls,omitempty"`
	IssuingCertificateURLs   []string `yaml:"issuing_certificate_urls,omitempty" json:"issuing_certificate_urls,omitempty"`
	CRLDistributionPointURLs []string `yaml:"crl_distribution_point_ur_ls,omitempty" json:"crl_distribution_point_ur_ls,omitempty"`
	CertificatePoliciesURLs  []string `yaml:"certificate_policies_urls,omitempty" json:"certificate_policies_urls,omitempty"`
}

func (v Config) Subject() pkix.Name {
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
	if len(v.CommonName) > 0 {
		result.CommonName = v.CommonName
	}

	return result
}

func (v Config) extraExtensions() []pkix.Extension {
	var result []pkix.Extension

	if len(v.CertificatePoliciesURLs) > 0 {
		result = append(result, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 32},
			Critical: false,
			Value:    marshalPolicyCPSUrl(stringsPrepare(v.CertificatePoliciesURLs)...),
		})
	} else {
		result = append(result, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 32, 0},
			Critical: false,
		})
	}

	return result
}

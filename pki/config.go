/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

// Config contains the X.509 subject fields, signature algorithm, and certificate
// URLs used when generating certificates. A zero SignatureAlgorithm in a
// signing operation inherits the issuer's algorithm where supported.
type Config struct {
	SignatureAlgorithm x509.SignatureAlgorithm `json:"signature_algorithm" yaml:"signature_algorithm"`

	Organization       string `json:"organization,omitempty"        yaml:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty" yaml:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"             yaml:"country,omitempty"`
	Province           string `json:"province,omitempty"            yaml:"province,omitempty"`
	Locality           string `json:"locality,omitempty"            yaml:"locality,omitempty"`
	StreetAddress      string `json:"street_address,omitempty"      yaml:"street_address,omitempty"`
	PostalCode         string `json:"postal_code,omitempty"         yaml:"postal_code,omitempty"`
	CommonName         string `json:"common_name,omitempty"         yaml:"common_name,omitempty"`

	OCSPServerURLs           []string `json:"ocsp_server_ur_ls,omitempty"            yaml:"ocsp_server_ur_ls,omitempty"`
	IssuingCertificateURLs   []string `json:"issuing_certificate_urls,omitempty"     yaml:"issuing_certificate_urls,omitempty"`
	CRLDistributionPointURLs []string `json:"crl_distribution_point_ur_ls,omitempty" yaml:"crl_distribution_point_ur_ls,omitempty"`
	CertificatePoliciesURLs  []string `json:"certificate_policies_urls,omitempty"    yaml:"certificate_policies_urls,omitempty"`
}

// Subject returns the distinguished name represented by the subject fields.
// Empty fields are omitted; each configured attribute is represented by one
// value.
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

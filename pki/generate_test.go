/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki_test

import (
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"go.osspkg.com/casecheck"

	"go.osspkg.com/encrypt/pki"
)

func TestUnit_Generate_ECDSA(t *testing.T) {
	rootCa, err := pki.NewCA(
		pki.Config{
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			CommonName:         "Test Root CA",
		},
		time.Hour*24*365*10,
		time.Now().Unix(),
		1,
	)
	casecheck.NoError(t, err)
	dump(t, rootCa)

	subCa, err := pki.NewIntermediateCA(
		pki.Config{
			SignatureAlgorithm:       x509.ECDSAWithSHA256,
			CommonName:               "Test Web CA",
			OCSPServerURLs:           []string{"http://ocsp.test.com"},
			CRLDistributionPointURLs: []string{"http://pki.test.com/cert.crl"},
			IssuingCertificateURLs:   []string{"http://pki.test.com/cert.crt"},
			CertificatePoliciesURLs:  []string{"http://pki.test.com/policy.pdf"},
		},
		*rootCa,
		time.Hour*24*365*5,
		time.Now().Unix(),
	)
	casecheck.NoError(t, err)
	dump(t, subCa)

	crt, err := pki.NewCRT(
		pki.Config{
			SignatureAlgorithm:       x509.ECDSAWithSHA256,
			CommonName:               "Test Web Ltd",
			OCSPServerURLs:           []string{"http://ocsp.test.com"},
			CRLDistributionPointURLs: []string{"http://pki.test.com/cert.crl"},
			IssuingCertificateURLs:   []string{"http://pki.test.com/cert.crt"},
			CertificatePoliciesURLs:  []string{"http://pki.test.com/policy.pdf"},
		},
		*subCa,
		time.Hour*24*90,
		time.Now().Unix(),
		"localhost",
	)
	casecheck.NoError(t, err)
	dump(t, crt)
}

func TestUnit_Generate_RSA(t *testing.T) {
	rootCa, err := pki.NewCA(
		pki.Config{
			SignatureAlgorithm:      x509.SHA384WithRSA,
			CommonName:              "Test Root CA",
			CertificatePoliciesURLs: []string{"http://pki.test.com/policy.pdf"},
		},
		time.Hour*24*365*10,
		time.Now().Unix(),
		1,
	)
	casecheck.NoError(t, err)
	dump(t, rootCa)

	subCa, err := pki.NewIntermediateCA(
		pki.Config{
			SignatureAlgorithm:       x509.SHA384WithRSA,
			CommonName:               "Test Web CA",
			CertificatePoliciesURLs:  []string{"http://pki.test.com/policy.pdf"},
			OCSPServerURLs:           []string{"http://ocsp.test.com"},
			CRLDistributionPointURLs: []string{"http://pki.test.com/cert.crl"},
			IssuingCertificateURLs:   []string{"http://pki.test.com/cert.crt"},
		},
		*rootCa,
		time.Hour*24*365*5,
		time.Now().Unix(),
	)
	casecheck.NoError(t, err)
	dump(t, subCa)

	crt, err := pki.NewCRT(
		pki.Config{
			SignatureAlgorithm:       x509.SHA384WithRSA,
			CommonName:               "Test Web Ltd",
			CertificatePoliciesURLs:  []string{"http://pki.test.com/policy.pdf"},
			OCSPServerURLs:           []string{"http://ocsp.test.com"},
			CRLDistributionPointURLs: []string{"http://pki.test.com/cert.crl"},
			IssuingCertificateURLs:   []string{"http://pki.test.com/cert.crt"},
		},
		*subCa,
		time.Hour*24*90,
		time.Now().Unix(),
		"localhost",
	)
	casecheck.NoError(t, err)
	dump(t, crt)
}

func TestUnit_SignCSR(t *testing.T) {
	rootCa, err := pki.NewCA(
		pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA512, CommonName: "Test Root CA"},
		time.Hour*24*365*10,
		time.Now().Unix(),
		1,
	)
	casecheck.NoError(t, err)
	dump(t, rootCa)

	subCa, err := pki.NewIntermediateCA(
		pki.Config{CommonName: "Test Web CA"},
		*rootCa,
		time.Hour*24*365*5,
		time.Now().Unix(),
	)
	casecheck.NoError(t, err)
	dump(t, subCa)

	csr, err := pki.NewCSR(x509.SHA384WithRSAPSS, "localhost")
	casecheck.NoError(t, err)

	crt, err := pki.SignCSR(pki.Config{}, *subCa, *csr.Csr, time.Hour*24*90, time.Now().Unix())
	casecheck.NoError(t, err)

	dump(t, &pki.Certificate{Crt: crt, Key: csr.Key})
}

func dump(t *testing.T, crt *pki.Certificate) {
	kb, err := pki.MarshalKeyPEM(crt.Key)
	casecheck.NoError(t, err)
	cb, err := pki.MarshalCrtPEM(*crt.Crt)
	casecheck.NoError(t, err)
	dumpCertificateInfo(crt.Crt)
	fmt.Println(string(kb))
	fmt.Println(string(cb))
}

func dumpCertificateInfo(cert *x509.Certificate) {
	fmt.Println("-------------------------------------------------------------------------")
	fmt.Println("                       ИНФОРМАЦИЯ О СЕРТИФИКАТЕ")
	fmt.Println("-------------------------------------------------------------------------")
	fmt.Printf("Субъект (Subject):               %v\n", cert.Subject.ToRDNSequence())
	fmt.Printf("SubjectKeyId:                    %x\n", cert.SubjectKeyId)
	fmt.Printf("Издатель (Issuer):               %v\n", cert.Issuer.ToRDNSequence())
	fmt.Printf("AuthorityKeyId:                  %x\n", cert.AuthorityKeyId)
	fmt.Printf("Общее имя (Common Name):         %s\n", cert.Subject.CommonName)
	fmt.Printf("Серийный номер:                  %s\n", cert.SerialNumber.String())
	fmt.Printf("Действителен с:                  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Действителен до:                 %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("DNS SANs:                        %v\n", cert.DNSNames)
	fmt.Printf("IP SANs:                         %v\n", cert.IPAddresses)
	fmt.Printf("Алгоритм подписи:                %v\n", cert.SignatureAlgorithm.String())
	fmt.Printf("Алгоритм публичного ключа:       %v\n", cert.PublicKeyAlgorithm.String())
	fmt.Printf("Базовое использование ключа:     %v\n", cert.KeyUsage)
	fmt.Printf("Расширенное использование ключа: %v\n", cert.ExtKeyUsage)
	fmt.Printf("Является CA:                     %t\n", cert.IsCA)
	fmt.Printf("Макс. длина пути (MaxPathLen):   %d\n", cert.MaxPathLen)
	fmt.Printf("CRL:                             %v\n", cert.CRLDistributionPoints)
	fmt.Printf("OCSP:                            %v\n", cert.OCSPServer)
	fmt.Printf("Certificate URL:                 %v\n", cert.IssuingCertificateURL)
	fmt.Println("-------------------------------------------------------------------------")
}

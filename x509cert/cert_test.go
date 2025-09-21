/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package x509cert_test

import (
	"crypto"
	x510 "crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"go.osspkg.com/casecheck"
	"golang.org/x/crypto/ocsp"

	"go.osspkg.com/encrypt/x509cert"
)

func TestUnit_X509(t *testing.T) {
	t.SkipNow()

	fmt.Println(time.Now().Unix(), time.Now().UnixNano())

	conf := x509cert.Config{
		Organization:          "Demo Inc.",
		CRLDistributionPoints: []string{"https://crl.demo.com/"},
		OCSPServer:            []string{"https://ocsp.demo.com"},
		SignatureAlgorithm:    x510.SHA384WithRSA,
	}

	ca, err := x509cert.NewCA(conf, nil, 2048, time.Hour*24*365*10, 1, "Root CA")
	casecheck.NoError(t, err)
	cacpem, err := ca.Cert.EncodePEM()
	casecheck.NoError(t, err)
	fmt.Println(string(cacpem))
	//cakpem, err := ca.Key.EncodePEM()
	//casecheck.NoError(t, err)
	//fmt.Println(string(cakpem))

	ica, err := x509cert.NewCA(conf, &ca, 2048, time.Hour*24*365*5, 1, "Intermediate CA")
	casecheck.NoError(t, err)
	icacpem, err := ica.Cert.EncodePEM()
	casecheck.NoError(t, err)
	fmt.Println(string(icacpem))

	crt, err := x509cert.NewCert(conf, ica, 2048, time.Hour*24*90, time.Now().UnixNano(), "example.com", "*.example.com")
	casecheck.NoError(t, err)
	crtcpem, err := crt.Cert.EncodePEM()
	casecheck.NoError(t, err)
	fmt.Println(string(crtcpem))
	//crtkpem, err := crt.Key.EncodePEM()
	//casecheck.NoError(t, err)
	//fmt.Println(string(crtkpem))

	algs := []crypto.Hash{
		crypto.MD4,
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
		crypto.SHA512_224,
		crypto.SHA512_256,
		crypto.SHA3_224,
		crypto.SHA3_256,
		crypto.SHA3_384,
		crypto.SHA3_512,
		crypto.RIPEMD160,
		crypto.BLAKE2s_256,
		crypto.BLAKE2b_256,
		crypto.BLAKE2b_384,
		crypto.BLAKE2b_512,
	}
	for _, alg := range algs {
		fmt.Println(alg.String(), alg.Available())

		fp, err := crt.Cert.FingerPrint(alg)
		casecheck.NoError(t, err)
		fmt.Println("FingerPrint", hex.EncodeToString(fp))

		inh, err := crt.Cert.IssuerNameHash(alg)
		casecheck.NoError(t, err)
		fmt.Println("IssuerNameHash", hex.EncodeToString(inh))

		ikh, err := crt.Cert.IssuerKeyHash(alg)
		casecheck.NoError(t, err)
		fmt.Println("IssuerKeyHash", hex.EncodeToString(ikh))
	}

	req, err := ocsp.CreateRequest(crt.Cert.Certificate, ca.Cert.Certificate, nil)
	casecheck.NoError(t, err)
	req1, err := ocsp.ParseRequest(req)
	casecheck.NoError(t, err)

	fmt.Println(req1.SerialNumber.Int64(), "IssuerNameHash", hex.EncodeToString(req1.IssuerNameHash),
		"IssuerKeyHash", hex.EncodeToString(req1.IssuerKeyHash))

	b, err := ca.Cert.IssuerNameHash(crypto.SHA1)
	casecheck.NoError(t, err)
	fmt.Println("IssuerNameHash", hex.EncodeToString(b))

	b, err = ca.Cert.IssuerKeyHash(crypto.SHA1)
	casecheck.NoError(t, err)
	fmt.Println("IssuerKeyHash", hex.EncodeToString(b))
}

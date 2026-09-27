//nolint:testpackage // These tests need package-private helpers and data structures.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

//nolint:revive // This test groups related coverage cases for one API.
func TestAlgorithmTypeChecksAndPairs(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		algorithm Algorithm
		key       crypto.Signer
		public    crypto.PublicKey
	}{
		{name: "ecdsa", algorithm: &_ecdsa{}, key: ecdsaKey, public: &ecdsaKey.PublicKey},
		{name: "rsa", algorithm: &_rsa{}, key: rsaKey, public: &rsaKey.PublicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.algorithm.IsPrivateKey(tc.key) {
				t.Fatal("private key not recognized")
			}
			if tc.algorithm.IsPrivateKey(nil) {
				t.Fatal("nil private key recognized")
			}
			cert := x509.Certificate{PublicKey: tc.public}
			if !tc.algorithm.IsCertificate(cert) {
				t.Fatal("certificate public key not recognized")
			}
			if tc.algorithm.IsCertificate(x509.Certificate{PublicKey: &rsaKey.PublicKey}) && tc.name == "ecdsa" {
				t.Fatal("wrong certificate key recognized")
			}
			request := x509.CertificateRequest{PublicKey: tc.public}
			if !tc.algorithm.IsRequest(request) {
				t.Fatal("request public key not recognized")
			}
			if tc.algorithm.IsRequest(x509.CertificateRequest{}) {
				t.Fatal("empty request recognized")
			}
			if !tc.algorithm.IsValidPair(tc.key, cert) {
				t.Fatal("matching key pair rejected")
			}
			var other crypto.Signer = rsaKey
			if tc.name == "rsa" {
				other = ecdsaKey
			}
			if tc.algorithm.IsValidPair(other, cert) {
				t.Fatal("mismatched key pair accepted")
			}
			wrongCert := x509.Certificate{PublicKey: &ecdsaKey.PublicKey}
			if tc.name == "ecdsa" {
				wrongCert.PublicKey = &rsaKey.PublicKey
			}
			if tc.algorithm.IsValidPair(tc.key, wrongCert) {
				t.Fatal("wrong certificate key type accepted")
			}
		})
	}
	if _, err := (&_ecdsa{}).Generate(x509.SHA256WithRSA); err == nil {
		t.Fatal("ECDSA Generate accepted RSA algorithm")
	}
	if _, err := (&_rsa{}).Generate(x509.ECDSAWithSHA256); err == nil {
		t.Fatal("RSA Generate accepted ECDSA algorithm")
	}
}

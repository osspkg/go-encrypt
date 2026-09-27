//nolint:testpackage // These tests need package-private helpers and data structures.
package xocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func testCertificate(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "xocsp test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestRequestRoundTripAndErrors(t *testing.T) {
	issuer, _ := testCertificate(t)
	leaf, _ := testCertificate(t)
	leaf.SerialNumber = big.NewInt(77)
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		raw, err := CreateRequest(leaf, issuer, &RequestOptions{Hash: hash})
		if err != nil {
			t.Fatalf("CreateRequest(%v): %v", hash, err)
		}
		req, err := ParseRequest(raw)
		if err != nil {
			t.Fatalf("ParseRequest(%v): %v", hash, err)
		}
		if req.HashAlgorithm != hash || req.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			t.Fatalf("request mismatch: %#v", req)
		}
	}
	if _, err := CreateRequest(leaf, issuer, &RequestOptions{Hash: crypto.MD5}); err == nil {
		t.Fatal("CreateRequest accepted unsupported hash")
	}
	if _, err := (&Request{HashAlgorithm: crypto.MD5}).Marshal(); err == nil {
		t.Fatal("Marshal accepted unsupported hash")
	}
	for _, raw := range [][]byte{nil, {0x30, 0x00}, {0x30, 0x03, 0x30, 0x01, 0x00}} {
		if _, err := ParseRequest(raw); err == nil {
			t.Errorf("ParseRequest accepted %x", raw)
		}
	}
}

//nolint:revive // This test groups related coverage cases for one API.
func TestResponseRoundTripStatusesAndErrors(t *testing.T) {
	issuer, key := testCertificate(t)
	leaf, _ := testCertificate(t)
	now := time.Now().Truncate(time.Minute).UTC()
	for _, status := range []int{Good, Unknown, Revoked} {
		template := Response{Status: status, SerialNumber: leaf.SerialNumber, ThisUpdate: now, NextUpdate: now.Add(time.Hour), IssuerHash: crypto.SHA256, Certificate: issuer, RevokedAt: now.Add(-time.Minute), RevocationReason: KeyCompromise}
		raw, err := CreateResponse(Success, issuer, issuer, template, key)
		if err != nil {
			t.Fatalf("CreateResponse(%d): %v", status, err)
		}
		parsed, err := ParseResponse(raw, issuer)
		if err != nil {
			t.Fatalf("ParseResponse(%d): %v", status, err)
		}
		if parsed.Status != status || parsed.SerialNumber.Cmp(leaf.SerialNumber) != 0 || parsed.Certificate == nil {
			t.Fatalf("response mismatch: %#v", parsed)
		}
		if status == Revoked && parsed.RevocationReason != KeyCompromise {
			t.Fatalf("reason = %d", parsed.RevocationReason)
		}
		if _, err := ParseResponseForCert(raw, leaf, issuer); err != nil {
			t.Fatalf("ParseResponseForCert: %v", err)
		}
		if _, err := ParseResponseForCert(raw, nil, nil); err != nil {
			t.Fatalf("ParseResponseForCert without issuer: %v", err)
		}
	}
	if _, err := CreateResponse(InternalError, issuer, issuer, Response{}, key); err == nil {
		t.Fatal("error status response accepted as basic response")
	}
	if _, err := ParseResponse(nil, nil); err == nil {
		t.Fatal("ParseResponse accepted malformed input")
	}
	for _, raw := range [][]byte{{0x30, 0x03, 0x0a, 0x01, 0x02}, {0x30, 0x03, 0x0a, 0x01, 0x00}} {
		if _, err := ParseResponse(raw, nil); err == nil {
			t.Errorf("ParseResponse accepted invalid response %x", raw)
		}
	}
	unknownStatus, err := asn1.Marshal(responseASN1{Status: 99})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResponse(unknownStatus, nil); err == nil {
		t.Fatal("ParseResponse accepted unknown status")
	}
	if _, err := CreateResponse(Success, issuer, issuer, Response{IssuerHash: crypto.MD5}, key); err == nil {
		t.Fatal("CreateResponse accepted unsupported issuer hash")
	}
	if _, err := CreateResponse(Success, issuer, issuer, Response{SignatureAlgorithm: x509.ECDSAWithSHA512, IssuerHash: crypto.SHA256}, key); err == nil {
		t.Fatal("CreateResponse accepted mismatched signing algorithm")
	}
}

//nolint:revive // This test groups related coverage cases for one API.
func TestAlgorithmHelpersAndErrors(t *testing.T) {
	_, key := testCertificate(t)
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		pub := &ecdsa.PublicKey{Curve: curve, X: big.NewInt(1), Y: big.NewInt(1)}
		if _, _, err := signingParamsForPublicKey(pub, 0); err != nil {
			t.Errorf("curve %s: %v", curve.Params().Name, err)
		}
	}
	rsaPublic := &rsa.PublicKey{N: big.NewInt(3233), E: 17}
	for _, alg := range []x509.SignatureAlgorithm{x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA} {
		if _, _, err := signingParamsForPublicKey(rsaPublic, alg); err != nil {
			t.Errorf("RSA algorithm %v: %v", alg, err)
		}
	}
	if _, _, err := signingParamsForPublicKey(&key.PublicKey, x509.SHA256WithRSA); err == nil {
		t.Fatal("accepted mismatched signature algorithm")
	}
	if _, _, err := signingParamsForPublicKey(&key.PublicKey, x509.MD2WithRSA); err == nil {
		t.Fatal("accepted hashless signature algorithm")
	}
	if _, _, err := signingParamsForPublicKey(&key.PublicKey, x509.SignatureAlgorithm(999)); err == nil {
		t.Fatal("accepted unknown signature algorithm")
	}
	if _, _, err := signingParamsForPublicKey(struct{}{}, 0); err == nil {
		t.Fatal("accepted unsupported public key type")
	}
	if got := getSignatureAlgorithmFromOID(asn1.ObjectIdentifier{1, 2, 3}); got != x509.UnknownSignatureAlgorithm {
		t.Fatalf("unknown signature OID mapped to %v", got)
	}
	if getHashAlgorithmFromOID(asn1.ObjectIdentifier{1, 2, 3}) != 0 || getOIDFromHashAlgorithm(crypto.MD5) != nil {
		t.Fatal("unknown hash mapping unexpectedly succeeded")
	}
	if got := (*RequestOptions)(nil).hash(); got != crypto.SHA1 {
		t.Fatalf("nil options hash = %v", got)
	}
	if got := (&RequestOptions{}).hash(); got != crypto.SHA1 {
		t.Fatalf("zero hash = %v", got)
	}
	if (ResponseStatus(7)).String() != "unknown OCSP status: 7" {
		t.Fatal("unexpected unknown status string")
	}
	if (ResponseError{Status: TryLater}).Error() != "ocsp: error from server: try later" {
		t.Fatal("unexpected ResponseError text")
	}
	if ParseError("bad").Error() != "bad" {
		t.Fatal("unexpected ParseError text")
	}
}

func TestCreateRequestDefaultsAndSignatureCheck(t *testing.T) {
	issuer, key := testCertificate(t)
	leaf, _ := testCertificate(t)
	raw, err := CreateRequest(leaf, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseRequest(raw)
	if err != nil || req.HashAlgorithm != crypto.SHA1 {
		t.Fatalf("default request hash=%v err=%v", req.HashAlgorithm, err)
	}
	response, err := CreateResponse(Success, issuer, issuer, Response{Status: Good, SerialNumber: leaf.SerialNumber, ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseResponse(response, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignatureFrom(issuer); err != nil {
		t.Fatal(err)
	}
	other, _ := testCertificate(t)
	if err := parsed.CheckSignatureFrom(other); err == nil {
		t.Fatal("CheckSignatureFrom accepted wrong issuer")
	}
}

func encodedFixture(t *testing.T, data responseData) []byte {
	t.Helper()
	algorithm := pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA256}
	basic, err := asn1.Marshal(basicResponse{TBSResponseData: data, SignatureAlgorithm: algorithm, Signature: asn1.BitString{Bytes: []byte{1}, BitLength: 8}})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := asn1.Marshal(responseASN1{Status: 0, Response: responseBytes{ResponseType: idPKIXOCSPBasic, Response: basic}})
	if err != nil {
		t.Fatal(err)
	}
	return outer
}

func fixtureData() responseData {
	nameDER, _ := asn1.Marshal(pkix.RDNSequence{})
	return responseData{
		RawResponderID: asn1.RawValue{Class: asn1ClassContextSpecific, Tag: asn1TagResponderName, IsCompound: true, Bytes: nameDER},
		ProducedAt:     time.Now().UTC(),
		Responses:      []singleResponse{{CertID: certID{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: hashOIDs[crypto.SHA1]}, SerialNumber: big.NewInt(7)}, Good: true, ThisUpdate: time.Now().UTC()}},
	}
}

func TestParseRequestStructuralErrors(t *testing.T) {
	empty, err := asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(empty); err == nil {
		t.Fatal("accepted request without request list")
	}
	unknownHash, err := asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{RequestList: []request{{Cert: certID{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}, SerialNumber: big.NewInt(9)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(unknownHash); err == nil {
		t.Fatal("accepted request with unknown hash")
	}
	valid, err := (&Request{HashAlgorithm: crypto.SHA256, SerialNumber: big.NewInt(8)}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(append(valid, 0)); err == nil {
		t.Fatal("accepted trailing request data")
	}
}

//nolint:revive // This test groups related coverage cases for one API.
func TestParseResponseStructuralErrorsAndSelections(t *testing.T) {
	data := fixtureData()
	if _, err := ParseResponseForCert(encodedFixture(t, data), &x509.Certificate{SerialNumber: big.NewInt(99)}, nil); err == nil {
		t.Fatal("accepted missing serial")
	}
	data.Responses = nil
	if _, err := ParseResponse(encodedFixture(t, data), nil); err == nil {
		t.Fatal("accepted empty response list")
	}
	data = fixtureData()
	data.Responses = append(data.Responses, data.Responses[0])
	if _, err := ParseResponse(encodedFixture(t, data), nil); err == nil {
		t.Fatal("accepted multiple statuses through ParseResponse")
	}
	if _, err := ParseResponseForCert(encodedFixture(t, data), &x509.Certificate{SerialNumber: big.NewInt(7)}, nil); err != nil {
		t.Fatalf("selected matching status: %v", err)
	}

	data = fixtureData()
	data.RawResponderID = asn1.RawValue{Class: asn1ClassContextSpecific, Tag: 7, IsCompound: true, Bytes: []byte{0x30, 0}}
	if _, err := ParseResponse(encodedFixture(t, data), nil); err == nil {
		t.Fatal("accepted unknown responder tag")
	}
	data = fixtureData()
	data.RawResponderID = asn1.RawValue{Class: asn1ClassContextSpecific, Tag: asn1TagResponderName, IsCompound: true, Bytes: []byte{0xff}}
	if _, err := ParseResponse(encodedFixture(t, data), nil); err == nil {
		t.Fatal("accepted invalid responder name")
	}
	data = fixtureData()
	data.RawResponderID = asn1.RawValue{Class: asn1ClassContextSpecific, Tag: asn1TagKeyHash, IsCompound: true, Bytes: []byte{0xff}}
	if _, err := ParseResponse(encodedFixture(t, data), nil); err == nil {
		t.Fatal("accepted invalid responder key hash")
	}
	data = fixtureData()
	data.Responses[0].SingleExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Critical: true}}
	if _, err := ParseResponse(encodedFixture(t, data), nil); err == nil {
		t.Fatal("accepted critical single-response extension")
	}
	data = fixtureData()
	data.Responses[0].CertID.HashAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
	if _, err := ParseResponse(encodedFixture(t, data), nil); err == nil {
		t.Fatal("accepted unknown issuer hash")
	}
	if _, err := ParseResponse(append(encodedFixture(t, fixtureData()), 0), nil); err == nil {
		t.Fatal("accepted trailing response data")
	}
}

func TestResponseStatusStrings(t *testing.T) {
	for status, want := range map[ResponseStatus]string{Success: "success", Malformed: "malformed", InternalError: "internal error", TryLater: "try later", SignatureRequired: "signature required", Unauthorized: "unauthorized"} {
		if got := status.String(); got != want {
			t.Errorf("%d.String()=%q want %q", status, got, want)
		}
	}
}

func TestParseResponseKeyHashResponderID(t *testing.T) {
	data := fixtureData()
	keyHash, err := asn1.Marshal([]byte("responder-key-hash"))
	if err != nil {
		t.Fatal(err)
	}
	data.RawResponderID = asn1.RawValue{Class: asn1ClassContextSpecific, Tag: asn1TagKeyHash, IsCompound: true, Bytes: keyHash}
	parsed, err := ParseResponse(encodedFixture(t, data), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.ResponderKeyHash) != "responder-key-hash" {
		t.Fatalf("key hash = %q", parsed.ResponderKeyHash)
	}
}

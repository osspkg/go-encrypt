package pki_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.osspkg.com/encrypt/pki"
	"go.osspkg.com/encrypt/pki/internal/xocsp"
)

type coverageResolver struct {
	response *pki.OCSPResponse
	err      error
	called   int
}

func (r *coverageResolver) OCSPStatusResolve(context.Context, *pki.OCSPRequest) (*pki.OCSPResponse, error) {
	r.called++
	return r.response, r.err
}

//nolint:revive // This test groups related coverage cases for one API.
func TestOCSPHandlerSuccessAndResolverErrors(t *testing.T) {
	ca, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, 24*time.Hour, 41, 0)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.NewCRT(pki.Config{}, *ca, time.Hour, 42, "ocsp.example.test")
	if err != nil {
		t.Fatal(err)
	}
	requestDER, err := xocsp.CreateRequest(leaf.Crt, ca.Crt, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("good", func(t *testing.T) {
		resolver := &coverageResolver{response: &pki.OCSPResponse{Status: pki.OCSPStatusGood}}
		server := &pki.OCSPServer{CA: *ca, Resolver: resolver, UpdateInterval: time.Hour}
		recorder := httptest.NewRecorder()
		server.HTTPHandler(recorder, httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(requestDER)))
		if recorder.Code != 200 || recorder.Header().Get("Content-Type") != "application/ocsp-response" {
			t.Fatalf("status=%d headers=%v body=%x", recorder.Code, recorder.Header(), recorder.Body.Bytes())
		}
		parsed, err := xocsp.ParseResponse(recorder.Body.Bytes(), ca.Crt)
		if err != nil || parsed.Status != xocsp.Good {
			t.Fatalf("parsed=%#v err=%v", parsed, err)
		}
		if resolver.called != 1 {
			t.Fatalf("resolver calls=%d", resolver.called)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		resolver := &coverageResolver{response: &pki.OCSPResponse{Status: pki.OCSPStatusRevoked, RevokedAt: time.Now().Add(-time.Minute), RevocationReason: pki.OCSPRevocationReasonKeyCompromise}}
		server := &pki.OCSPServer{CA: *ca, Resolver: resolver, UpdateInterval: time.Hour}
		recorder := httptest.NewRecorder()
		server.HTTPHandler(recorder, httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(requestDER)))
		parsed, err := xocsp.ParseResponse(recorder.Body.Bytes(), ca.Crt)
		if err != nil || parsed.Status != xocsp.Revoked || parsed.RevocationReason != xocsp.KeyCompromise {
			t.Fatalf("parsed=%#v err=%v", parsed, err)
		}
	})

	for _, tc := range []struct {
		name        string
		body        []byte
		response    *pki.OCSPResponse
		resolverErr error
		status      int
	}{
		{name: "malformed", body: []byte("bad"), response: &pki.OCSPResponse{Status: pki.OCSPStatusUnknown}, status: 500},
		{name: "resolver error", body: requestDER, response: &pki.OCSPResponse{}, resolverErr: errors.New("resolver failed"), status: 200},
		{name: "nil resolver response", body: requestDER, status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &coverageResolver{response: tc.response, err: tc.resolverErr}
			var reported error
			server := &pki.OCSPServer{CA: *ca, Resolver: resolver, UpdateInterval: time.Hour, OnError: func(err error) { reported = err }}
			recorder := httptest.NewRecorder()
			server.HTTPHandler(recorder, httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(tc.body)))
			if recorder.Code != tc.status {
				t.Fatalf("status=%d want=%d", recorder.Code, tc.status)
			}
			if reported == nil {
				t.Fatal("OnError was not called")
			}
			if tc.status == 200 {
				_, err := xocsp.ParseResponse(recorder.Body.Bytes(), ca.Crt)
				var responseErr xocsp.ResponseError
				if !errors.As(err, &responseErr) || responseErr.Status != xocsp.InternalError {
					t.Fatalf("response error = %v, want internal error", err)
				}
			}
		})
	}
}

func TestOCSPResolverReceivesRequestAndUnknownReasonDefaults(t *testing.T) {
	ca, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, 24*time.Hour, 51, 0)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.NewCRT(pki.Config{}, *ca, time.Hour, 52, "reason.example.test")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := xocsp.CreateRequest(leaf.Crt, ca.Crt, &xocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &coverageResolver{response: &pki.OCSPResponse{Status: pki.OCSPStatusRevoked, RevokedAt: time.Now(), RevocationReason: pki.OCSPRevocationReason(99)}}
	server := &pki.OCSPServer{CA: *ca, Resolver: resolver, UpdateInterval: time.Hour}
	recorder := httptest.NewRecorder()
	server.HTTPHandler(recorder, httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(raw)))
	parsed, err := xocsp.ParseResponse(recorder.Body.Bytes(), ca.Crt)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.IssuerHash != crypto.SHA1 || parsed.RevocationReason != xocsp.Unspecified || parsed.SerialNumber.Cmp(big.NewInt(52)) != 0 {
		t.Fatalf("unexpected response: %#v", parsed)
	}
}

type brokenResponseWriter struct{ header http.Header }

func (w *brokenResponseWriter) Header() http.Header     { return w.header }
func (*brokenResponseWriter) Write([]byte) (int, error) { return 0, errors.New("client disconnected") }
func (*brokenResponseWriter) WriteHeader(int)           {}

func TestOCSPHandlerReportsResponseWriteFailure(t *testing.T) {
	ca, err := pki.NewCA(pki.Config{SignatureAlgorithm: x509.ECDSAWithSHA256}, time.Hour, 80, 0)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.NewCRT(pki.Config{}, *ca, time.Minute, 81, "write.example.test")
	if err != nil {
		t.Fatal(err)
	}
	request, err := xocsp.CreateRequest(leaf.Crt, ca.Crt, nil)
	if err != nil {
		t.Fatal(err)
	}
	var reported error
	server := &pki.OCSPServer{CA: *ca, Resolver: &coverageResolver{response: &pki.OCSPResponse{Status: pki.OCSPStatusGood}}, OnError: func(err error) { reported = err }}
	server.HTTPHandler(&brokenResponseWriter{header: make(http.Header)}, httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(request)))
	if reported == nil || !strings.Contains(reported.Error(), "write response") {
		t.Fatalf("OnError = %v", reported)
	}
}

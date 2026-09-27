package pki_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.osspkg.com/encrypt/pki"
)

type rejectingOCSPResolver struct {
	called bool
}

func (r *rejectingOCSPResolver) OCSPStatusResolve(context.Context, *pki.OCSPRequest) (*pki.OCSPResponse, error) {
	r.called = true
	return nil, nil
}

func TestOCSPHandlerRejectsOversizedRequest(t *testing.T) {
	resolver := &rejectingOCSPResolver{}
	server := &pki.OCSPServer{Resolver: resolver}
	request := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(make([]byte, (1<<20)+1)))
	response := httptest.NewRecorder()

	server.HTTPHandler(response, request)

	if resolver.called {
		t.Fatal("resolver called for oversized request")
	}
	if response.Code != 413 {
		t.Fatalf("want status 413 for oversized request, got %d", response.Code)
	}
}

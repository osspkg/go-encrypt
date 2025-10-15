/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package x509cert

import (
	"context"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

type OCSPStatusResolver interface {
	OCSPStatusResolve(ctx context.Context, r *ocsp.Request) (OCSPStatus, error)
}

type OCSPStatus int

const (
	OCSPStatusUnknown OCSPStatus = ocsp.Unknown
	OCSPStatusGood    OCSPStatus = ocsp.Good
	OCSPStatusRevoked OCSPStatus = ocsp.Revoked
)

type OCSPServer struct {
	CA             Cert
	Resolver       OCSPStatusResolver
	UpdateInterval time.Duration
}

func (v *OCSPServer) HTTPHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	req, err := ocsp.ParseRequest(raw)
	if err != nil {
		http.Error(w, "invalid ocsp data", http.StatusBadRequest)
		return
	}

	status, err := v.Resolver.OCSPStatusResolve(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := ocsp.Response{
		Status:       int(status),
		SerialNumber: req.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(v.UpdateInterval),
		ProducedAt:   time.Now(),
	}

	resp, err := ocsp.CreateResponse(v.CA.Cert.Certificate, v.CA.Cert.Certificate, response, v.CA.Key.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(resp) //nolint:errcheck
}

/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"context"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"time"

	"go.osspkg.com/encrypt/pki/internal/xocsp"
	"golang.org/x/crypto/ocsp"
)

type OCSPStatusResolver interface {
	OCSPStatusResolve(ctx context.Context, r *ocsp.Request) (OCSPStatus, error)
}

type OCSPStatus int

const (
	OCSPStatusUnknown      OCSPStatus = ocsp.Unknown
	OCSPStatusGood         OCSPStatus = ocsp.Good
	OCSPStatusRevoked      OCSPStatus = ocsp.Revoked
	OCSPStatusServerFailed OCSPStatus = ocsp.ServerFailed
)

type OCSPServer struct {
	CA             Certificate
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

	req, err := xocsp.ParseRequest(raw)
	if err != nil {
		http.Error(w, "invalid ocsp data", http.StatusBadRequest)
		return
	}

	var nonce []byte
	for _, extension := range req.Extensions {
		if extension.Id.Equal(xocsp.OIDNonce) {
			nonce = extension.Value
		}
	}

	status, err := v.Resolver.OCSPStatusResolve(r.Context(), &ocsp.Request{
		HashAlgorithm:  req.HashAlgorithm,
		IssuerNameHash: req.IssuerNameHash,
		IssuerKeyHash:  req.IssuerKeyHash,
		SerialNumber:   req.SerialNumber,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	template := xocsp.Response{
		Status:       int(status),
		SerialNumber: req.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(v.UpdateInterval),
		ProducedAt:   time.Now(),
		Certificate:  v.CA.Crt,
	}

	if len(nonce) > 0 {
		template.Extensions = append(template.Extensions, pkix.Extension{
			Id:       xocsp.OIDNonce,
			Critical: false,
			Value:    nonce,
		})
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:       xocsp.OIDNonce,
			Critical: false,
			Value:    nonce,
		})
	}

	resp, err := xocsp.CreateResponse(v.CA.Crt, v.CA.Crt, template, v.CA.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(resp) //nolint:errcheck
}

/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"go.osspkg.com/ioutils"

	"go.osspkg.com/encrypt/pki/internal/xocsp"
)

type OCSPStatusResolver interface {
	OCSPStatusResolve(ctx context.Context, r *OCSPRequest) (*OCSPResponse, error)
}

type OCSPStatus int

const (
	OCSPStatusGood    OCSPStatus = xocsp.Good
	OCSPStatusUnknown OCSPStatus = xocsp.Unknown
	OCSPStatusRevoked OCSPStatus = xocsp.Revoked
)

type OCSPRevocationReason int

const (
	// OCSPRevocationReasonUnspecified
	// Unspecified (code 0): A general, default reason when a more specific one isn't applicable.
	OCSPRevocationReasonUnspecified OCSPRevocationReason = 0
	// OCSPRevocationReasonKeyCompromise
	// Key Compromise (code 1): The most critical reason, indicating that the
	// private key associated with the certificate has been compromised or is suspected of being compromised.
	OCSPRevocationReasonKeyCompromise OCSPRevocationReason = 1
	// OCSPRevocationReasonCACompromise
	// CA Compromise (code 2): The certificate authority that issued the certificate has been compromised.
	OCSPRevocationReasonCACompromise OCSPRevocationReason = 2
	// OCSPRevocationReasonAffiliationChanged
	// Affiliation Changed (code 3): The certificate holder's relationship with the organization has changed,
	// such as termination of employment.
	OCSPRevocationReasonAffiliationChanged OCSPRevocationReason = 3
	// OCSPRevocationReasonSuperseded
	// Superseded (code 4): The certificate has been replaced by a new one,
	// often because of a normal lifecycle event like a password change or a legal name change.
	OCSPRevocationReasonSuperseded OCSPRevocationReason = 4
	// OCSPRevocationReasonCessationOfOperation
	// Cessation of Operation (code 5): The system or service for which the certificate was issued is no longer in
	// operation.
	OCSPRevocationReasonCessationOfOperation OCSPRevocationReason = 5
	// OCSPRevocationReasonCertificateHold
	// Certificate Hold (code 6): Used for temporary invalidation, such as when a certificate's status is under review.
	OCSPRevocationReasonCertificateHold OCSPRevocationReason = 6
)

type (
	OCSPServer struct {
		CA             Certificate
		Resolver       OCSPStatusResolver
		UpdateInterval time.Duration
		OnError        func(err error)
	}
	OCSPRequest struct {
		HashAlgorithm  crypto.Hash
		IssuerNameHash []byte
		IssuerKeyHash  []byte
		SerialNumber   *big.Int
		Extensions     []pkix.Extension
	}

	OCSPResponse struct {
		Status           OCSPStatus
		RevokedAt        time.Time
		RevocationReason OCSPRevocationReason
	}
)

func (v *OCSPServer) HTTPHandler(w http.ResponseWriter, r *http.Request) {
	reqStatus := xocsp.Success

	template := xocsp.Response{
		Status:      int(OCSPStatusUnknown),
		ThisUpdate:  time.Now().Truncate(time.Minute).UTC(),
		NextUpdate:  time.Now().Add(v.UpdateInterval).Truncate(time.Minute).UTC(),
		Certificate: v.CA.Crt,
	}

	var (
		err error
		raw []byte
	)

	if raw, err = ioutils.ReadAll(r.Body); err == nil {

		var req *xocsp.Request
		if req, err = xocsp.ParseRequest(raw); err == nil {

			template.SerialNumber = req.SerialNumber

			for _, extension := range req.Extensions {
				if extension.Id.Equal(xocsp.OIDNonce) {
					template.Extensions = append(template.Extensions, pkix.Extension{
						Id:       xocsp.OIDNonce,
						Critical: false,
						Value:    extension.Value,
					})
					break
				}
			}

			var resp *OCSPResponse
			if resp, err = v.Resolver.OCSPStatusResolve(r.Context(), &OCSPRequest{
				HashAlgorithm:  req.HashAlgorithm,
				IssuerNameHash: req.IssuerNameHash,
				IssuerKeyHash:  req.IssuerKeyHash,
				SerialNumber:   req.SerialNumber,
				Extensions:     req.Extensions,
			}); err == nil {

				template.Status = int(resp.Status)

				if resp.Status == OCSPStatusRevoked {
					template.RevokedAt = resp.RevokedAt

					switch resp.RevocationReason {
					case OCSPRevocationReasonKeyCompromise, OCSPRevocationReasonCACompromise,
						OCSPRevocationReasonAffiliationChanged, OCSPRevocationReasonSuperseded,
						OCSPRevocationReasonCessationOfOperation, OCSPRevocationReasonCertificateHold:
						template.RevocationReason = int(resp.RevocationReason)
					default:
						template.RevocationReason = int(OCSPRevocationReasonUnspecified)
					}
				}
			}
		}
	}

	if err != nil {
		if v.OnError != nil {
			v.OnError(fmt.Errorf("ocsp: request processing: %w", err))
		}
		reqStatus = xocsp.InternalError
	}

	resp, err := xocsp.CreateResponse(reqStatus, v.CA.Crt, v.CA.Crt, template, v.CA.Key)
	if err != nil {
		if v.OnError != nil {
			v.OnError(fmt.Errorf("ocsp: create response: %w", err))
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	if _, err = w.Write(resp); err != nil {
		if v.OnError != nil {
			v.OnError(fmt.Errorf("ocsp: write response: %w", err))
		}
	}
}

/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"go.osspkg.com/ioutils"

	"go.osspkg.com/encrypt/pki/internal/xocsp"
)

const maxOCSPRequestBytes = 1 << 20

// OCSPStatusResolver resolves the revocation status of an OCSP request. The
// implementation should honor ctx cancellation and return a non-nil response
// when err is nil.
type OCSPStatusResolver interface {
	OCSPStatusResolve(ctx context.Context, r *OCSPRequest) (*OCSPResponse, error)
}

// OCSPStatus represents the certificate status reported by OCSP.
type OCSPStatus int

const (
	// OCSPStatusGood indicates the certificate is not revoked.
	OCSPStatusGood OCSPStatus = xocsp.Good
	// OCSPStatusUnknown indicates the responder does not know the certificate status.
	OCSPStatusUnknown OCSPStatus = xocsp.Unknown
	// OCSPStatusRevoked indicates the certificate has been revoked.
	OCSPStatusRevoked OCSPStatus = xocsp.Revoked
)

// OCSPRevocationReason represents the reason a certificate was revoked.
type OCSPRevocationReason int

const (
	// OCSPRevocationReasonUnspecified is the default reason when no specific revocation reason applies.
	// Unspecified (code 0): A general, default reason when a more specific one isn't applicable.
	OCSPRevocationReasonUnspecified OCSPRevocationReason = 0
	// OCSPRevocationReasonKeyCompromise indicates that the certificate private key was compromised.
	// Key Compromise (code 1): The most critical reason, indicating that the
	// private key associated with the certificate has been compromised or is suspected of being compromised.
	OCSPRevocationReasonKeyCompromise OCSPRevocationReason = 1
	// OCSPRevocationReasonCACompromise indicates that the issuing CA was compromised.
	// CA Compromise (code 2): The certificate authority that issued the certificate has been compromised.
	OCSPRevocationReasonCACompromise OCSPRevocationReason = 2
	// OCSPRevocationReasonAffiliationChanged indicates that the subject affiliation changed.
	// Affiliation Changed (code 3): The certificate holder's relationship with the organization has changed,
	// such as termination of employment.
	OCSPRevocationReasonAffiliationChanged OCSPRevocationReason = 3
	// OCSPRevocationReasonSuperseded indicates that the certificate was replaced.
	// Superseded (code 4): The certificate has been replaced by a new one,
	// often because of a normal lifecycle event like a password change or a legal name change.
	OCSPRevocationReasonSuperseded OCSPRevocationReason = 4
	// OCSPRevocationReasonCessationOfOperation indicates that the certificate subject ceased operation.
	// Cessation of Operation (code 5): The system or service for which the certificate was issued is no longer in
	// operation.
	OCSPRevocationReasonCessationOfOperation OCSPRevocationReason = 5
	// OCSPRevocationReasonCertificateHold indicates that the certificate is temporarily suspended.
	// Certificate Hold (code 6): Used for temporary invalidation, such as when a certificate's status is under review.
	OCSPRevocationReasonCertificateHold OCSPRevocationReason = 6
)

type (
	// OCSPServer serves OCSP status responses for certificates issued by its CA.
	OCSPServer struct {
		CA             Certificate
		Resolver       OCSPStatusResolver
		UpdateInterval time.Duration
		OnError        func(err error)
	}
	// OCSPRequest contains the certificate identifier and extensions in an OCSP request.
	OCSPRequest struct {
		HashAlgorithm  crypto.Hash
		IssuerNameHash []byte
		IssuerKeyHash  []byte
		SerialNumber   *big.Int
		Extensions     []pkix.Extension
	}

	// OCSPResponse contains the status and revocation details for a certificate.
	OCSPResponse struct {
		Status           OCSPStatus
		RevokedAt        time.Time
		RevocationReason OCSPRevocationReason
	}
)

// HTTPHandler handles an HTTP OCSP request and writes a signed response. It
// reads at most 1 MiB from the request body, returning HTTP 413 for larger
// bodies. Processing and response-writing failures are passed to OnError when
// it is set. Configure CA and Resolver before serving requests; UpdateInterval
// controls the response NextUpdate time.
func (v *OCSPServer) HTTPHandler(w http.ResponseWriter, r *http.Request) {
	template := xocsp.Response{
		Status:      int(OCSPStatusUnknown),
		ThisUpdate:  time.Now().Truncate(time.Minute).UTC(),
		NextUpdate:  time.Now().Add(v.UpdateInterval).Truncate(time.Minute).UTC(),
		Certificate: v.CA.Crt,
	}

	raw, err := ioutils.ReadAll(http.MaxBytesReader(w, r.Body, maxOCSPRequestBytes))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
	} else {
		err = v.resolveRequest(r.Context(), raw, &template)
	}

	reqStatus := xocsp.Success
	if err != nil {
		v.reportError(fmt.Errorf("ocsp: request processing: %w", err))
		reqStatus = xocsp.InternalError
	}

	resp, err := xocsp.CreateResponse(reqStatus, v.CA.Crt, v.CA.Crt, template, v.CA.Key)
	if err != nil {
		v.reportError(fmt.Errorf("ocsp: create response: %w", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	if _, err = w.Write(resp); err != nil {
		v.reportError(fmt.Errorf("ocsp: write response: %w", err))
	}
}

func (v *OCSPServer) resolveRequest(ctx context.Context, raw []byte, template *xocsp.Response) error {
	req, err := xocsp.ParseRequest(raw)
	if err != nil {
		return err
	}
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

	resp, err := v.Resolver.OCSPStatusResolve(ctx, &OCSPRequest{
		HashAlgorithm:  req.HashAlgorithm,
		IssuerNameHash: req.IssuerNameHash,
		IssuerKeyHash:  req.IssuerKeyHash,
		SerialNumber:   req.SerialNumber,
		Extensions:     req.Extensions,
	})
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("OCSP resolver returned nil response")
	}

	template.Status = int(resp.Status)
	if resp.Status != OCSPStatusRevoked {
		return nil
	}
	template.RevokedAt = resp.RevokedAt

	switch resp.RevocationReason {
	case OCSPRevocationReasonKeyCompromise, OCSPRevocationReasonCACompromise,
		OCSPRevocationReasonAffiliationChanged, OCSPRevocationReasonSuperseded,
		OCSPRevocationReasonCessationOfOperation, OCSPRevocationReasonCertificateHold:
		template.RevocationReason = int(resp.RevocationReason)
	default:
		template.RevocationReason = int(OCSPRevocationReasonUnspecified)
	}
	return nil
}

func (v *OCSPServer) reportError(err error) {
	if v.OnError != nil {
		v.OnError(err)
	}
}

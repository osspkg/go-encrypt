/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"

	_ "golang.org/x/crypto/blake2s"
	_ "golang.org/x/crypto/md4"
	_ "golang.org/x/crypto/ripemd160"
	_ "golang.org/x/crypto/sha3"
)

type policyQualifierInfo struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         string `asn1:"ia5"`
}
type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	PolicyQualifiers []policyQualifierInfo `asn1:"optional"`
}

func marshalPolicyCPSUrl(urls ...string) []byte {
	cpsInfo := policyInformation{
		PolicyIdentifier: asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1},
		PolicyQualifiers: make([]policyQualifierInfo, 0, len(urls)),
	}

	for _, url := range urls {
		cpsInfo.PolicyQualifiers = append(cpsInfo.PolicyQualifiers, policyQualifierInfo{
			PolicyQualifierID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1},
			Qualifier:         url,
		})
	}

	bytes, _ := asn1.Marshal([]policyInformation{cpsInfo})
	return bytes
}

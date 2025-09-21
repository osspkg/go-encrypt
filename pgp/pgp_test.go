/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pgp_test

import (
	"bytes"
	"crypto"
	"testing"

	"go.osspkg.com/casecheck"
	"go.osspkg.com/encrypt/pgp"
)

func TestUnit_PGP(t *testing.T) {
	conf := pgp.Config{
		Name:    "Test Name",
		Email:   "Test Email",
		Comment: "Test Comment",
	}
	crt, err := pgp.NewCert(conf, crypto.MD5, 1024, "tool", "dewep utils")
	casecheck.NoError(t, err)
	t.Log(string(crt.Private), string(crt.Public))

	in := bytes.NewBufferString("Hello world")
	out := &bytes.Buffer{}

	sig := pgp.New()
	err = sig.SetKey(crt.Private, "")
	casecheck.NoError(t, err)

	sig.SetHash(crypto.MD5, 1024)
	err = sig.Sign(in, out)
	casecheck.NoError(t, err)

	t.Log(out.String())
}

/*
 *  Copyright (c) 2024 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package x509_test

import (
	"testing"
	"time"

	"go.osspkg.com/encrypt/x509"
)

func TestUnit_X509(t *testing.T) {
	conf := &x509.Config{
		Organization: "Demo Inc.",
	}

	crt, err := x509.NewCA(conf, time.Hour*24*365*10, "Demo Root R1")
	if err != nil {
		t.Fatalf(err.Error())
	}
	t.Log(string(crt.Private), string(crt.Public))

	crt, err = x509.NewCert(conf, time.Hour*24*90, 2, crt, "example.com", "*.example.com")
	if err != nil {
		t.Fatalf(err.Error())
	}
	t.Log(string(crt.Private), string(crt.Public))
}

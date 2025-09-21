/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package hash_test

import (
	"crypto/md5"
	"strings"
	"testing"

	"go.osspkg.com/casecheck"

	"go.osspkg.com/encrypt/hash"
)

type testData struct {
	A string
}

func TestUnit_Adapter(t *testing.T) {
	ha := &hash.Adapter{H: md5.New()}

	casecheck.NoError(t, ha.Read(strings.NewReader("123")))
	casecheck.Equal(t, "202cb962ac59075b964b07152d234b70", ha.ResultHex())
	casecheck.Equal(t, "ICy5YqxZB1uWSwcVLSNLcA==", ha.ResultBase64())
	ha.Reset()

	casecheck.NoError(t, ha.Write([]byte("123")))
	casecheck.Equal(t, "202cb962ac59075b964b07152d234b70", ha.ResultHex())
	casecheck.Equal(t, "ICy5YqxZB1uWSwcVLSNLcA==", ha.ResultBase64())
	ha.Reset()

	casecheck.NoError(t, ha.WriteString("123"))
	casecheck.Equal(t, "202cb962ac59075b964b07152d234b70", ha.ResultHex())
	casecheck.Equal(t, "ICy5YqxZB1uWSwcVLSNLcA==", ha.ResultBase64())
	ha.Reset()

	casecheck.NoError(t, ha.WriteAny(1, 2, 3))
	casecheck.Equal(t, "202cb962ac59075b964b07152d234b70", ha.ResultHex())
	casecheck.Equal(t, "ICy5YqxZB1uWSwcVLSNLcA==", ha.ResultBase64())
	ha.Reset()

	casecheck.NoError(t, ha.WriteAny(1, 2, 3))
	casecheck.Equal(t, "202cb962ac59075b964b07152d234b70", ha.ResultHex())
	casecheck.Equal(t, "ICy5YqxZB1uWSwcVLSNLcA==", ha.ResultBase64())
	ha.Reset()

	casecheck.NoError(t, ha.WriteAny(&testData{A: "123"}))
	casecheck.Equal(t, "5c2f64f6fa624f78f67911662b727e7a", ha.ResultHex())
	casecheck.Equal(t, "XC9k9vpiT3j2eRFmK3J+eg==", ha.ResultBase64())
	ha.Reset()

	casecheck.NoError(t, ha.WriteAny(&testData{A: "123"}))
	casecheck.Equal(t, "5c2f64f6fa624f78f67911662b727e7a", ha.ResultHex())
	casecheck.Equal(t, "XC9k9vpiT3j2eRFmK3J+eg==", ha.ResultBase64())
	ha.Reset()
}

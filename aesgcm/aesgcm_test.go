/*
 *  Copyright (c) 2024 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package aesgcm_test

import (
	"fmt"
	"testing"

	"go.osspkg.com/casecheck"
	"go.osspkg.com/encrypt/aesgcm"
	"go.osspkg.com/random"
)

func TestUnit_Codec(t *testing.T) {
	rndKey := random.Bytes(32)
	c, err := aesgcm.New(rndKey)
	casecheck.NoError(t, err)
	enc1, err := c.Encrypt([]byte("Hello World!"))
	fmt.Println("Hello World!", string(enc1))
	casecheck.NoError(t, err)
	dec1, err := c.Decrypt(enc1)
	casecheck.NoError(t, err)
	casecheck.Equal(t, []byte("Hello World!"), dec1)

	rndKey = random.BytesOf(32, []byte("йфяцычувскамепинртгоьшлбщдзхъ"))
	c, err = aesgcm.New(rndKey)
	casecheck.NoError(t, err)
	enc1, err = c.Encrypt([]byte("Hello World!"))
	fmt.Println("Hello World!", string(enc1))
	casecheck.NoError(t, err)
	dec1, err = c.Decrypt(enc1)
	casecheck.NoError(t, err)
	casecheck.Equal(t, []byte("Hello World!"), dec1)
}

func Benchmark_Codec(b *testing.B) {
	key := random.Bytes(32)
	message := []byte("Hello World!")

	c, err := aesgcm.New(key)
	if err != nil {
		b.FailNow()
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			enc, er := c.Encrypt(message)
			if er != nil {
				b.FailNow()
			}

			_, er = c.Decrypt(enc)
			if er != nil {
				b.FailNow()
			}
		}
	})
}

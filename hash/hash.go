/*
 *  Copyright (c) 2024 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
)

func SHA1(v string) string {
	h := sha1.New()
	io.WriteString(h, v) // nolint: errcheck
	return fmt.Sprintf("%x", h.Sum(nil))
}

func SHA256(v string) string {
	h := sha256.New()
	io.WriteString(h, v) // nolint: errcheck
	return fmt.Sprintf("%x", h.Sum(nil))
}

func SHA512(v string) string {
	h := sha512.New()
	io.WriteString(h, v) // nolint: errcheck
	return fmt.Sprintf("%x", h.Sum(nil))
}

func MD5(v string) string {
	h := md5.New()
	io.WriteString(h, v) // nolint: errcheck
	return fmt.Sprintf("%x", h.Sum(nil))
}

/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package pki

import (
	_ "crypto/md5"    // Registers the digest for crypto.Hash.Available.
	_ "crypto/sha1"   // Registers the digest for crypto.Hash.Available.
	_ "crypto/sha256" // Registers the digest for crypto.Hash.Available.
	_ "crypto/sha512" // Registers the digest for crypto.Hash.Available.

	_ "golang.org/x/crypto/blake2s" // Registers the digest for crypto.Hash.Available.
	_ "golang.org/x/crypto/sha3"    // Registers the digest for crypto.Hash.Available.
)

const (
	privateFileMode = 0o600
	publicFileMode  = 0o644
)

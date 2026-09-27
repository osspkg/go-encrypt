/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

// Package hash provides adapters for hashing structured values.
package hash

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"reflect"
)

// Adapter writes data into H and exposes the resulting digest. Initialize H
// with a hash implementation such as sha256.New before using the Adapter.
type Adapter struct {
	H hash.Hash
}

// Read copies all data from r into H. It returns an error if H or r is nil or
// if reading from r fails.
func (a *Adapter) Read(r io.Reader) error {
	if a.H == nil {
		return errors.New("hash is nil")
	}
	if r == nil {
		return errors.New("reader is nil")
	}

	_, err := io.Copy(a.H, r)
	return err
}

// Write writes b to H. It returns an error if H is nil or the hash rejects the
// write.
func (a *Adapter) Write(b []byte) error {
	if a.H == nil {
		return errors.New("hash is nil")
	}

	_, err := a.H.Write(b)
	return err
}

// WriteString writes a string to the hash.
func (a *Adapter) WriteString(s string) error {
	if a.H == nil {
		return errors.New("hash is nil")
	}

	_, err := io.WriteString(a.H, s)
	return err
}

// WriteAny writes supported values to the hash.
func (a *Adapter) WriteAny(args ...any) error {
	if a.H == nil {
		return errors.New("hash is nil")
	}

	for _, arg := range args {
		ref := reflect.ValueOf(arg)
		if ref.Kind() == reflect.Ptr {
			ref = ref.Elem()
		}
		if _, err := fmt.Fprintf(a.H, "%#v", ref.Interface()); err != nil {
			return err
		}
	}

	return nil
}

// Result returns the current hash digest.
func (a *Adapter) Result() []byte {
	if a.H == nil {
		return nil
	}

	return a.H.Sum(nil)
}

// ResultHex returns the current hash digest as hexadecimal.
func (a *Adapter) ResultHex() string {
	if a.H == nil {
		return ""
	}

	return hex.EncodeToString(a.H.Sum(nil))
}

// ResultBase64 returns the current hash digest as base64.
func (a *Adapter) ResultBase64() string {
	if a.H == nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(a.H.Sum(nil))
}

// Reset resets the hash state.
func (a *Adapter) Reset() {
	if a.H == nil {
		return
	}

	a.H.Reset()
}

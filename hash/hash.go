/*
 *  Copyright (c) 2024-2025 Mikhail Knyazhev <markus621@yandex.ru>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

package hash

import (
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"reflect"
)

type Adapter struct {
	H hash.Hash
}

func (a *Adapter) Read(r io.Reader) error {
	if a.H == nil {
		return fmt.Errorf("hash is nil")
	}
	if r == nil {
		return fmt.Errorf("reader is nil")
	}

	_, err := io.Copy(a.H, r)
	return err
}

func (a *Adapter) Write(b []byte) error {
	if a.H == nil {
		return fmt.Errorf("hash is nil")
	}

	_, err := a.H.Write(b)
	return err
}

func (a *Adapter) WriteString(s string) error {
	if a.H == nil {
		return fmt.Errorf("hash is nil")
	}

	_, err := io.WriteString(a.H, s)
	return err
}

func (a *Adapter) WriteAny(args ...any) error {
	if a.H == nil {
		return fmt.Errorf("hash is nil")
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

func (a *Adapter) Result() []byte {
	if a.H == nil {
		return nil
	}

	return a.H.Sum(nil)
}

func (a *Adapter) ResultHex() string {
	if a.H == nil {
		return ""
	}

	return fmt.Sprintf("%x", a.H.Sum(nil))
}

func (a *Adapter) ResultBase64() string {
	if a.H == nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(a.H.Sum(nil))
}

func (a *Adapter) Reset() {
	if a.H == nil {
		return
	}

	a.H.Reset()
}

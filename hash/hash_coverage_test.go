package hash_test

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"go.osspkg.com/encrypt/hash"
)

type failingHash struct{}

var errWrite = errors.New("write failed")

func (failingHash) Write([]byte) (int, error) { return 0, errWrite }
func (failingHash) Sum(b []byte) []byte       { return b }
func (failingHash) Reset()                    {}
func (failingHash) Size() int                 { return 0 }
func (failingHash) BlockSize() int            { return 0 }

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type nilValue struct{}

func TestAdapterNilAndReaderErrors(t *testing.T) {
	a := &hash.Adapter{}
	if err := a.Read(strings.NewReader("x")); err == nil {
		t.Fatal("Read accepted nil hash")
	}
	if err := a.Read(nil); err == nil {
		t.Fatal("Read accepted nil reader")
	}
	if err := a.Read(failingReader{}); err == nil {
		t.Fatal("Read ignored reader error")
	}
	if err := a.Write([]byte("x")); err == nil {
		t.Fatal("Write accepted nil hash")
	}
	if err := a.WriteString("x"); err == nil {
		t.Fatal("WriteString accepted nil hash")
	}
	if err := a.WriteAny(nil); err == nil {
		t.Fatal("WriteAny accepted nil hash")
	}
	if a.Result() != nil || a.ResultHex() != "" || a.ResultBase64() != "" {
		t.Fatal("nil hash returned a digest")
	}
	a.Reset()
}

func TestAdapterWriteErrorsAndNilPointers(t *testing.T) {
	a := &hash.Adapter{H: failingHash{}}
	if err := a.Write([]byte("x")); !errors.Is(err, errWrite) {
		t.Fatalf("Write error = %v, want %v", err, errWrite)
	}
	if err := a.WriteString("x"); !errors.Is(err, errWrite) {
		t.Fatalf("WriteString error = %v, want %v", err, errWrite)
	}

	a = &hash.Adapter{H: failingHash{}}
	if err := a.WriteAny("value"); !errors.Is(err, errWrite) {
		t.Fatalf("WriteAny error = %v, want %v", err, errWrite)
	}
	a = &hash.Adapter{H: sha256.New()}
	if err := a.WriteAny(nil); err == nil {
		t.Fatal("WriteAny accepted nil interface value")
	}
	var p *nilValue
	if err := a.WriteAny(p); err == nil {
		t.Fatal("WriteAny accepted nil pointer")
	}
}

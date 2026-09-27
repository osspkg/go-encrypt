/*
 *  Copyright (c) 2024-2026 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a BSD 3-Clause license that can be found in the LICENSE file.
 */

// Package pgp generates OpenPGP keys and creates cleartext signatures.
package pgp

import (
	"bytes"
	"crypto"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"go.osspkg.com/errors"
)

const (
	defaultRSABits = 4096
	headerPairSize = 2
)

type (
	// Config contains the identity used when generating an OpenPGP key.
	Config struct {
		Name, Email, Comment string
	}

	// Cert contains armored public and private OpenPGP keys.
	Cert struct {
		Public  []byte
		Private []byte
	}
)

type (
	store struct {
		key     *openpgp.Entity
		conf    *packet.Config
		headers map[string]string
	}

	// Signer loads an OpenPGP private key and creates cleartext signatures.
	Signer interface {
		// SetKey loads a private key from OpenPGP-armored bytes. passwd is used
		// only when the private key is encrypted.
		SetKey(b []byte, passwd string) error
		// SetKeyFromFile loads an armored private key from filename.
		SetKeyFromFile(filename string, passwd string) error
		// SetHash configures the hash and RSA key size used for signing and key
		// generation. The size applies only when generating a key.
		SetHash(hash crypto.Hash, bits int)
		// PublicKey returns the loaded key's public part in binary OpenPGP format.
		PublicKey() ([]byte, error)
		// PublicKeyBase64 returns the loaded key's public part in armored format.
		PublicKeyBase64() ([]byte, error)
		// Sign writes an OpenPGP cleartext signature of in to out.
		Sign(in io.Reader, out io.Writer) error
	}
)

// New creates a signer with SHA-512 and 4096-bit RSA defaults.
func New() Signer {
	return &store{
		conf: &packet.Config{
			DefaultHash: crypto.SHA512,
			RSABits:     defaultRSABits,
		},
		headers: make(map[string]string),
	}
}

// SetKey loads a private key from armored bytes.
func (v *store) SetKey(b []byte, passwd string) error {
	r := bytes.NewReader(b)
	return v.readKey(r, passwd)
}

// SetHash sets the hash and RSA key size used for signing and key generation.
func (v *store) SetHash(hash crypto.Hash, bits int) {
	v.conf.DefaultHash = hash
	v.conf.RSABits = bits
}

// SetHeaders sets armor headers for serialized keys.
func (v *store) SetHeaders(headers ...string) error {
	h, err := createHeaders(headers)
	if err != nil {
		return err
	}
	v.headers = mergeHeaders(v.headers, h)
	return nil
}

// SetKeyFromFile loads a private key from a file.
func (v *store) SetKeyFromFile(filename string, passwd string) error {
	r, err := os.Open(filename)
	if err != nil {
		return errors.Wrapf(err, "read key from file")
	}
	defer r.Close() // nolint: errcheck
	return v.readKey(r, passwd)
}

// PublicKey returns the public key in binary OpenPGP format.
func (v *store) PublicKey() ([]byte, error) {
	if v.key == nil {
		return nil, errors.New("key is empty")
	}

	var buf bytes.Buffer
	if err := v.key.Serialize(&buf); err != nil {
		return nil, errors.Wrapf(err, "serialize public key")
	}
	return buf.Bytes(), nil
}

// PublicKeyBase64 returns the public key in armored OpenPGP format.
func (v *store) PublicKeyBase64() ([]byte, error) {
	if v.key == nil {
		return nil, errors.New("key is empty")
	}

	var buf bytes.Buffer
	enc, err := armor.Encode(&buf, openpgp.PublicKeyType, v.headers)
	if err != nil {
		return nil, errors.Wrapf(err, "init armor encoder")
	}
	if err = v.key.Serialize(enc); err != nil {
		return nil, errors.Wrapf(err, "serialize public key")
	}
	if err = enc.Close(); err != nil {
		return nil, errors.Wrapf(err, "close armor encoder")
	}
	return buf.Bytes(), nil
}

func (v *store) readKey(r io.ReadSeeker, passwd string) error {
	block, err := armor.Decode(r)
	if err != nil {
		return errors.Wrapf(err, "armor decode key")
	}
	if block.Type != openpgp.PrivateKeyType {
		return errors.Wrapf(err, "invalid key type")
	}
	if _, err = r.Seek(0, 0); err != nil {
		return errors.Wrapf(err, "seek key file")
	}
	keys, err := openpgp.ReadArmoredKeyRing(r)
	if err != nil {
		return errors.Wrapf(err, "read armored key")
	}
	if len(keys) == 0 || keys[0] == nil || keys[0].PrivateKey == nil {
		return errors.New("private key is missing")
	}
	v.key = keys[0]
	if v.key.PrivateKey.Encrypted {
		if err = v.key.PrivateKey.Decrypt([]byte(passwd)); err != nil {
			return errors.Wrapf(err, "invalid password")
		}
	}
	v.headers = mergeHeaders(v.headers, block.Header)
	return nil
}

// Sign writes a cleartext signature for the input.
func (v *store) Sign(in io.Reader, out io.Writer) error {
	if v.key == nil {
		return errors.New("key is empty")
	}

	w, err := clearsign.Encode(out, v.key.PrivateKey, v.conf)
	if err != nil {
		return errors.Wrapf(err, "init")
	}
	if _, err = io.Copy(w, in); err != nil {
		return err
	}
	return w.Close()
}

func generatePrivateKey(key *openpgp.Entity, w io.Writer, headers map[string]string) error {
	enc, err := armor.Encode(w, openpgp.PrivateKeyType, headers)
	if err != nil {
		return errors.Wrapf(err, "init armor encoder")
	}
	defer enc.Close() // nolint: errcheck

	if err = key.SerializePrivate(enc, nil); err != nil {
		return errors.Wrapf(err, "serialize private key")
	}

	return nil
}

func generatePublicKey(key *openpgp.Entity, w io.Writer, headers map[string]string) error {
	enc, err := armor.Encode(w, openpgp.PublicKeyType, headers)
	if err != nil {
		return errors.Wrapf(err, "create OpenPGP armor")
	}
	defer enc.Close() // nolint: errcheck

	if err = key.Serialize(enc); err != nil {
		return errors.Wrapf(err, "serialize public key")
	}

	return nil
}

func setupIdentities(key *openpgp.Entity, c *packet.Config) error {
	// Sign all the identities
	for _, id := range key.Identities {
		id.SelfSignature.PreferredCompression = []uint8{1, 2, 3, 0}
		id.SelfSignature.PreferredHash = []uint8{2, 8, 10, 1, 3, 9, 11}
		id.SelfSignature.PreferredSymmetric = []uint8{9, 8, 7, 3, 2}

		if err := id.SelfSignature.SignUserId(id.UserId.Id, key.PrimaryKey, key.PrivateKey, c); err != nil {
			return err
		}
	}
	return nil
}

func createHeaders(v []string) (map[string]string, error) {
	if len(v)%2 != 0 {
		return nil, errors.New("odd headers count")
	}
	result := make(map[string]string, len(v)/headerPairSize)
	for i := 0; i < len(v); i += 2 {
		result[v[i]] = v[i+1]
	}
	return result, nil
}

func mergeHeaders(h ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range h {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// NewCert generates an OpenPGP certificate with the requested hash and RSA key
// size. It returns the public and private keys in armored form. Hashes that are
// unsupported or considered too weak for key generation are replaced with
// SHA-256.
func NewCert(c Config, hash crypto.Hash, bits int, headers ...string) (*Cert, error) {
	h, err := createHeaders(headers)
	if err != nil {
		return nil, errors.Wrapf(err, "parse headers")
	}

	// The maintained OpenPGP implementation rejects weak hashes such as MD5
	// when generating keys. Keep signing keys on SHA-256 or stronger.
	hash = supportedKeyHash(hash)

	conf := &packet.Config{
		DefaultHash: hash,
		RSABits:     bits,
	}

	key, err := openpgp.NewEntity(c.Name, c.Comment, c.Email, conf)
	if err != nil {
		return nil, errors.Wrapf(err, "generate entity")
	}

	if err = setupIdentities(key, conf); err != nil {
		return nil, errors.Wrapf(err, "setup entity")
	}

	var priv bytes.Buffer
	if err = generatePrivateKey(key, &priv, h); err != nil {
		return nil, errors.Wrapf(err, "generate private key")
	}

	var pub bytes.Buffer
	if err = generatePublicKey(key, &pub, h); err != nil {
		return nil, errors.Wrapf(err, "generate public key")
	}

	return &Cert{
		Public:  pub.Bytes(),
		Private: priv.Bytes(),
	}, nil
}

// NewCertSHA512 generates an OpenPGP certificate using SHA-512 and a 4096-bit
// RSA key. It returns the public and private keys in armored form.
func NewCertSHA512(c Config, headers ...string) (*Cert, error) {
	return NewCert(c, crypto.SHA512, defaultRSABits, headers...)
}

func supportedKeyHash(hash crypto.Hash) crypto.Hash {
	switch hash {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA3_256, crypto.SHA3_512:
		return hash
	default:
		return crypto.SHA256
	}
}

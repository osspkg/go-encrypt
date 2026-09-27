package pgp_test

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"go.osspkg.com/encrypt/pgp"
)

func TestSetKeyRejectsEmptyPrivateKeyring(t *testing.T) {
	var input bytes.Buffer
	block, err := armor.Encode(&input, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := block.Close(); err != nil {
		t.Fatal(err)
	}

	if err := pgp.New().SetKey(input.Bytes(), ""); err == nil {
		t.Fatal("SetKey accepted an empty private keyring")
	}
}

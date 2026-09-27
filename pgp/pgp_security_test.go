package pgp_test

import (
	"testing"

	"go.osspkg.com/encrypt/pgp"
)

func TestSetKeyRejectsEmptyPrivateKeyring(t *testing.T) {
	const emptyPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n=twTO\n-----END PGP PRIVATE KEY BLOCK-----\n"
	if err := pgp.New().SetKey([]byte(emptyPrivateKey), ""); err == nil {
		t.Fatal("SetKey accepted an empty private keyring")
	}
}

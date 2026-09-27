package main

import (
	"crypto/rand"
	"fmt"

	"go.osspkg.com/encrypt/aesgcm"
)

func main() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	codec, err := aesgcm.New(key)
	if err != nil {
		panic(err)
	}

	sealed, err := codec.Encrypt([]byte("secret message"))
	if err != nil {
		panic(err)
	}
	plain, err := codec.Decrypt(sealed)
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted: %s\n", plain)
}

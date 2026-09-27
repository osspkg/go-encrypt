package main

import (
	"crypto/sha256"
	"fmt"

	"go.osspkg.com/encrypt/hash"
)

func main() {
	digest := hash.Adapter{H: sha256.New()}
	if err := digest.WriteString("payload"); err != nil {
		panic(err)
	}
	fmt.Println(digest.ResultHex())
}

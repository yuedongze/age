package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"filippo.io/age"
)

func main() {
	pk, sk := age.SikeKeygen()
	pkEnc := base64.StdEncoding.EncodeToString(pk)
	skEnc := base64.StdEncoding.EncodeToString(sk)
	fmt.Fprintf(os.Stderr, "Public Key: sike-%s\n", pkEnc)
	fmt.Fprintf(os.Stdout, "SIKE-SECRET-KEY-%s\n", skEnc)
}

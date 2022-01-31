package age

// #cgo CFLAGS: -I/home/stevenyue/work/liboqs/build/include
// #cgo LDFLAGS: -L/home/stevenyue/work/liboqs/build/lib -loqs
//
// #include <oqs/oqs.h>
// #include <stdio.h>
import "C"

import (
	"encoding/base64"
	"unsafe"
)

func SikeKeygen() ([]byte, []byte) {
	kem := C.OQS_KEM_new(C.CString("SIKE-p434-compressed"))

	publicKey := make([]byte, kem.length_public_key)
	secretKey := make([]byte, kem.length_secret_key)
	C.OQS_KEM_keypair(kem, (*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])))

	return publicKey, secretKey
}

type SikeRecipient struct {
	publicKey []byte
	kem       *C.OQS_KEM
}

var _ Recipient = &SikeRecipient{}

func NewSikeRecipient(publicKeyEncoded string) (*SikeRecipient, error) {
	kem := C.OQS_KEM_new(C.CString("SIKE-p434-compressed"))
	pk := make([]byte, kem.length_public_key)
	_, err := base64.StdEncoding.Decode(pk, []byte(publicKeyEncoded))
	if err != nil {
		return nil, err
	}
	r := &SikeRecipient{
		publicKey: pk,
		kem:       kem,
	}
	return r, nil
}

func (r *SikeRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	sharedSecret := make([]byte, r.kem.length_shared_secret)
	ciphertext := make([]byte, r.kem.length_ciphertext)

	C.OQS_KEM_encaps(r.kem,
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
		(*C.uchar)(unsafe.Pointer(&r.publicKey[0])),
	)

	ct := make([]byte, r.kem.length_ciphertext+r.kem.length_shared_secret)
	copy(ct, ciphertext)
	for i := range sharedSecret {
		ct[int(r.kem.length_ciphertext)+i] = sharedSecret[i] ^ fileKey[i]
	}

	l := &Stanza{
		Type: "sike",
		Body: ct,
	}

	return []*Stanza{
		l,
	}, nil
}

type SikeIdentity struct {
	secretKey []byte
	kem       *C.OQS_KEM
}

var _ Identity = &SikeIdentity{}

func NewSikeIdentity(secretKeyEncoded string) (*SikeIdentity, error) {
	kem := C.OQS_KEM_new(C.CString("SIKE-p434-compressed"))
	sk := make([]byte, kem.length_secret_key)
	_, err := base64.StdEncoding.Decode(sk, []byte(secretKeyEncoded))
	if err != nil {
		return nil, err
	}
	r := &SikeIdentity{
		secretKey: sk,
		kem:       kem,
	}
	return r, nil
}

func (i *SikeIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	res := make([]byte, 0)

	for _, s := range stanzas {
		if s.Type != "sike" {
			continue
		}

		sharedSecret := make([]byte, i.kem.length_shared_secret)
		newCt := make([]byte, i.kem.length_ciphertext)
		copy(newCt, s.Body[:i.kem.length_ciphertext])
		C.OQS_KEM_decaps(i.kem,
			(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
			(*C.uchar)(unsafe.Pointer(&newCt[0])),
			(*C.uchar)(unsafe.Pointer(&i.secretKey[0])),
		)

		fileKey := make([]byte, i.kem.length_shared_secret)
		for j := range sharedSecret {
			fileKey[j] = sharedSecret[j] ^ s.Body[int(i.kem.length_ciphertext)+j]
		}
		res = append(res, fileKey...)
	}

	return res, nil
}

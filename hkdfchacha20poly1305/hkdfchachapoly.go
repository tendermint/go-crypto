package xchacha20poly1305

import (
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var sigma = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

type hkdfchacha20poly1305 struct {
	key [KeySize]byte
}

const (
	// KeySize is the size of the key used by this AEAD, in bytes.
	KeySize = 32
	// NonceSize is the size of the nonce used with this AEAD, in bytes.
	NonceSize = 24
	// HkdfInfo is the parameter used internally for Hkdf's info parameter.
	HkdfInfo = "TENDERMINT_SECRET_CONNECTION_FRAME_KEY_DERIVE"
)

//New xChaChapoly1305 AEAD with 24 byte nonces
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	ret := new(hkdfchacha20poly1305)
	copy(ret.key[:], key)
	return ret, nil

}
func (c *hkdfchacha20poly1305) NonceSize() int {
	return NonceSize
}

func (c *hkdfchacha20poly1305) Overhead() int {
	return 16
}

func (c *hkdfchacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("xchacha20poly1305: bad nonce length passed to Seal")
	}

	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("xchacha20poly1305: plaintext too large")
	}

	var subKey [KeySize]byte
	var hNonce [16]byte
	var subNonce [chacha20poly1305.NonceSize]byte
	copy(hNonce[:], nonce[:16])

	hash := sha256.New
	hkdf := hkdf.New(hash, c.key[:], hNonce[:], []byte(HkdfInfo))
	io.ReadFull(hkdf, subKey[:])
	// HChaCha20(&subKey, &hNonce, &c.key)

	chacha20poly1305, _ := chacha20poly1305.New(subKey[:])

	copy(subNonce[4:], nonce[16:])

	return chacha20poly1305.Seal(dst, subNonce[:], plaintext, additionalData)
}

func (c *hkdfchacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("hkdfchacha20poly1305: bad nonce length passed to Open")
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		return nil, fmt.Errorf("hkdfchacha20poly1305: ciphertext too large")
	}
	var subKey [KeySize]byte
	var hNonce [16]byte
	var subNonce [chacha20poly1305.NonceSize]byte
	copy(hNonce[:], nonce[:16])

	hash := sha256.New
	hkdf := hkdf.New(hash, c.key[:], hNonce[:], []byte(HkdfInfo))
	io.ReadFull(hkdf, subKey[:])
	// HChaCha20(&subKey, &hNonce, &c.key)

	chacha20poly1305, _ := chacha20poly1305.New(subKey[:])

	copy(subNonce[4:], nonce[16:])

	return chacha20poly1305.Open(dst, subNonce[:], ciphertext, additionalData)
}

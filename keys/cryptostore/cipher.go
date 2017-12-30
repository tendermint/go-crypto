package cryptostore

import (
	"github.com/pkg/errors"
	crypto "github.com/tendermint/go-crypto"
)

var (
	// SecretBox uses the algorithm from NaCL to store secrets securely
	SecretBox PrivKeyCipher = secretbox{}
	// Noop doesn't do any encryption, should only be used in test code
	Noop PrivKeyCipher = noop{}
)

// PrivKeyCipher is used to encrypt a PrivKey with a passphrase for storage.
// The passphrase should be used to derive a symmetric key for encryption
// using a secure key derivation function.
type PrivKeyCipher interface {
	Encrypt(key crypto.PrivKey, pass string) ([]byte, error)
	Decrypt(data []byte, pass string) (crypto.PrivKey, error)
}

// TODO: Sha256(Bcrypt(passphrase))
func secret(passphrase string) []byte {
	return crypto.Sha256([]byte(passphrase))
}

type secretbox struct{}

// Encrypt implements PrivKeyCipher.
// If pass is empty, it will return the unencrypted serialized private key.
func (e secretbox) Encrypt(key crypto.PrivKey, pass string) ([]byte, error) {
	if pass == "" {
		return key.Bytes(), nil
	}
	s := secret(pass)
	cipher := crypto.EncryptSymmetric(key.Bytes(), s)
	return cipher, nil
}

// Decrypt implements PrivKeyCipher.
func (e secretbox) Decrypt(data []byte, pass string) (key crypto.PrivKey, err error) {
	private := data
	if pass != "" {
		s := secret(pass)
		private, err = crypto.DecryptSymmetric(data, s)
		if err != nil {
			return crypto.PrivKey{}, errors.Wrap(err, "Invalid Passphrase")
		}
	}
	key, err = crypto.PrivKeyFromBytes(private)
	return key, errors.Wrap(err, "Invalid Passphrase")
}

type noop struct{}

// Encrypt implements PrivKeyCipher.
func (n noop) Encrypt(key crypto.PrivKey, pass string) ([]byte, error) {
	return key.Bytes(), nil
}

// Decrypt implements PrivKeyCipher.
func (n noop) Decrypt(data []byte, pass string) (crypto.PrivKey, error) {
	return crypto.PrivKeyFromBytes(data)
}

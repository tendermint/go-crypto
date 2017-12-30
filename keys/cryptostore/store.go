package cryptostore

import (
	crypto "github.com/tendermint/go-crypto"
	keys "github.com/tendermint/go-crypto/keys"
)

// keyStore is a keys.Storage that encrypts the keys.
type keyStore struct {
	cipher PrivKeyCipher
	store  keys.Storage
}

// Put encrypts the key and stores it.
func (ks keyStore) Put(name, pass string, key crypto.PrivKey) error {
	secret, err := ks.cipher.Encrypt(key, pass)
	if err != nil {
		return err
	}

	ki := info(name, key.PubKey())
	return ks.store.Put(name, secret, ki)
}

// Get fetches the encrypted key and decrypts it.
func (ks keyStore) Get(name, pass string) (crypto.PrivKey, keys.Info, error) {
	secret, info, err := ks.store.Get(name)
	if err != nil {
		return crypto.PrivKey{}, info, err
	}
	key, err := ks.cipher.Decrypt(secret, pass)
	return key, info, err
}

// List returns a list of keys in the store.
func (ks keyStore) List() (keys.Infos, error) {
	return ks.store.List()
}

// Delete deletes a key from the store.
// XXX: Should this require a passphrase?
func (ks keyStore) Delete(name string) error {
	return ks.store.Delete(name)
}

// info returns the keys.Info for this key.
func info(name string, pub crypto.PubKey) keys.Info {
	return keys.Info{
		Name:    name,
		Address: pub.Address(),
		PubKey:  pub,
	}
}

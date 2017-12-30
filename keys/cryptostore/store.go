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
	cipherText, err := ks.cipher.Encrypt(key, pass)
	if err != nil {
		return err
	}

	publicInfo := info(name, key.PubKey())
	return ks.store.Put(name, keys.KeyInfo{
		Public: publicInfo,
		Private: keys.PrivateInfo{
			CipherText: cipherText,
		},
	})
}

// Get fetches the encrypted key and decrypts it.
func (ks keyStore) Get(name, pass string) (crypto.PrivKey, keys.PublicInfo, error) {
	info, err := ks.store.Get(name)
	if err != nil {
		return crypto.PrivKey{}, keys.PublicInfo{}, err
	}
	key, err := ks.cipher.Decrypt(info.Private.CipherText, pass)
	return key, info.Public, err
}

// List returns a list of keys in the store.
func (ks keyStore) List() (keys.PublicInfos, error) {
	return ks.store.List()
}

// Delete deletes a key from the store.
// XXX: Should this require a passphrase?
func (ks keyStore) Delete(name string) error {
	return ks.store.Delete(name)
}

// info returns the keys.PublicInfo for this key.
func info(name string, pub crypto.PubKey) keys.PublicInfo {
	return keys.PublicInfo{
		Name:    name,
		Address: pub.Address(),
		PubKey:  pub,
	}
}

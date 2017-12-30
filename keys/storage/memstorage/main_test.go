package memstorage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	crypto "github.com/tendermint/go-crypto"
	keys "github.com/tendermint/go-crypto/keys"
)

func TestBasicCRUD(t *testing.T) {
	assert := assert.New(t)
	store := New()

	name := "foo"
	key := []byte("secret-key-here")
	pubkey := crypto.GenPrivKeyEd25519().PubKey()
	info := keys.KeyInfo{
		Public: keys.PublicInfo{
			Name:   name,
			PubKey: pubkey,
		},
		Private: keys.PrivateInfo{
			CipherText: key,
		},
	}

	// No data: Get and Delete return nothing
	_, err := store.Get(name)
	assert.NotNil(err)
	err = store.Delete(name)
	assert.NotNil(err)
	// List returns empty list
	l, err := store.List()
	assert.Nil(err)
	assert.Empty(l)

	// Putting the key in the  store must work
	err = store.Put(name, info)
	assert.Nil(err)
	// But a second time is a failure
	err = store.Put(name, info)
	assert.NotNil(err)

	// Now, we can get and list properly
	i, err := store.Get(name)
	assert.Nil(err)
	assert.Equal(key, i.Private.CipherText)
	assert.Equal(info.Public.Name, i.Public.Name)
	assert.Equal(info.Public.PubKey, i.Public.PubKey)
	assert.NotEmpty(i.Public.Address)
	l, err = store.List()
	assert.Nil(err)
	assert.Equal(1, len(l))
	assert.Equal(i.Public, l[0])

	// querying a non-existent key fails
	_, err = store.Get("badname")
	assert.NotNil(err)

	// We can only delete once
	err = store.Delete(name)
	assert.Nil(err)
	err = store.Delete(name)
	assert.NotNil(err)

	// and then Get and List don't work
	_, err = store.Get(name)
	assert.NotNil(err)
	// List returns empty list
	l, err = store.List()
	assert.Nil(err)
	assert.Empty(l)
}

/*
package memstorage provides a simple in-memory key store designed for
use in test cases, particularly to isolate them from the filesystem,
concurrency, and cleanup issues.
*/
package memstorage

import (
	"github.com/pkg/errors"
	keys "github.com/tendermint/go-crypto/keys"
)

type MemStore map[string]keys.KeyInfo

// New creates an instance of file-based key storage with tight permissions
func New() MemStore {
	return MemStore{}
}

// assert MemStore satisfies keys.Storage
var _ keys.Storage = MemStore{}

// Put adds the given key, returns an error if it another key
// is already stored under this name
func (s MemStore) Put(name string, info keys.KeyInfo) error {
	if _, ok := s[name]; ok {
		return errors.Errorf("Key named '%s' already exists", name)
	}
	s[name] = info
	return nil
}

// Get returns the key stored under the name, or returns an error if not present
func (s MemStore) Get(name string) (keys.KeyInfo, error) {
	info, ok := s[name]
	if !ok {
		return keys.KeyInfo{}, errors.Errorf("Key named '%s' doesn't exist", name)
	}
	return info.Format(), nil
}

// List returns the public info of all keys in the MemStore in unsorted order
func (s MemStore) List() (keys.PublicInfos, error) {
	res := make([]keys.PublicInfo, len(s))
	i := 0
	for _, info := range s {
		res[i] = info.Public.Format()
		i++
	}
	return res, nil
}

// Delete removes the named key from the MemStore, raising an error if it
// wasn't present yet.
func (s MemStore) Delete(name string) error {
	_, ok := s[name]
	if !ok {
		return errors.Errorf("Key named '%s' doesn't exist", name)
	}
	delete(s, name)
	return nil
}

package crypto

import (
	data "github.com/tendermint/go-data"
	"github.com/tendermint/go-wire"
)

func PrivKeyFromBytes(privKeyBytes []byte) (privKey PrivKey, err error) {
	err = wire.ReadBinaryBytes(privKeyBytes, &privKey)
	return
}

//----------------------------------------

type PrivKey struct {
	PrivKeyInner `json:"unwrap"`
}

var privKeyMapper = data.NewMapper(PrivKey{})

// DO NOT USE THIS INTERFACE.
// You probably want to use PubKey
type PrivKeyInner interface {
	AssertIsPrivKeyInner()
	Sign(msg []byte) Signature
	PubKey() PubKey
	Equals(PrivKey) bool
	Wrap() PrivKey
}

func (p PrivKey) Bytes() []byte {
	return wire.BinaryBytes(p)
}

func (p PrivKey) MarshalJSON() ([]byte, error) {
	return privKeyMapper.ToJSON(p.PrivKeyInner)
}

func (p *PrivKey) UnmarshalJSON(data []byte) (err error) {
	parsed, err := privKeyMapper.FromJSON(data)
	if err == nil && parsed != nil {
		p.PrivKeyInner = parsed.(PrivKeyInner)
	}
	return
}

// Unwrap recovers the concrete interface safely (regardless of levels of embeds)
func (p PrivKey) Unwrap() PrivKeyInner {
	pk := p.PrivKeyInner
	for wrap, ok := pk.(PrivKey); ok; wrap, ok = pk.(PrivKey) {
		pk = wrap.PrivKeyInner
	}
	return pk
}

func (p PrivKey) Empty() bool {
	return p.PrivKeyInner == nil
}

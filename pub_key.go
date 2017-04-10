package crypto

import (
	data "github.com/tendermint/go-data"
	"github.com/tendermint/go-wire"
)

func PubKeyFromBytes(pubKeyBytes []byte) (pubKey PubKey, err error) {
	err = wire.ReadBinaryBytes(pubKeyBytes, &pubKey)
	return
}

//----------------------------------------

type PubKey struct {
	PubKeyInner `json:"unwrap"`
}

var pubKeyMapper = data.NewMapper(PubKey{})

// DO NOT USE THIS INTERFACE.
// You probably want to use PubKey
type PubKeyInner interface {
	AssertIsPubKeyInner()
	Address() []byte
	KeyString() string
	VerifyBytes(msg []byte, sig Signature) bool
	Equals(PubKey) bool
	Wrap() PubKey
}

func (p PubKey) Bytes() []byte {
	return wire.BinaryBytes(p)
}

func (pk PubKey) MarshalJSON() ([]byte, error) {
	return pubKeyMapper.ToJSON(pk.PubKeyInner)
}

func (pk *PubKey) UnmarshalJSON(data []byte) (err error) {
	parsed, err := pubKeyMapper.FromJSON(data)
	if err == nil && parsed != nil {
		pk.PubKeyInner = parsed.(PubKeyInner)
	}
	return
}

// Unwrap recovers the concrete interface safely (regardless of levels of embeds)
func (pk PubKey) Unwrap() PubKeyInner {
	pkI := pk.PubKeyInner
	for wrap, ok := pkI.(PubKey); ok; wrap, ok = pkI.(PubKey) {
		pkI = wrap.PubKeyInner
	}
	return pkI
}

func (p PubKey) Empty() bool {
	return p.PubKeyInner == nil
}

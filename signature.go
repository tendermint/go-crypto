package crypto

import (
	data "github.com/tendermint/go-data"
	"github.com/tendermint/go-wire"
)

func SignatureFromBytes(sigBytes []byte) (sig Signature, err error) {
	err = wire.ReadBinaryBytes(sigBytes, &sig)
	return
}

//----------------------------------------

type Signature struct {
	SignatureInner `json:"unwrap"`
}

var sigMapper = data.NewMapper(Signature{})

// DO NOT USE THIS INTERFACE.
// You probably want to use Signature.
type SignatureInner interface {
	AssertIsSignatureInner()
	IsZero() bool
	String() string
	Equals(Signature) bool
	Wrap() Signature
}

func (s Signature) Bytes() []byte {
	return wire.BinaryBytes(s)
}

func (sig Signature) MarshalJSON() ([]byte, error) {
	return sigMapper.ToJSON(sig.SignatureInner)
}

func (sig *Signature) UnmarshalJSON(data []byte) (err error) {
	parsed, err := sigMapper.FromJSON(data)
	if err == nil && parsed != nil {
		sig.SignatureInner = parsed.(SignatureInner)
	}
	return
}

// Unwrap recovers the concrete interface safely (regardless of levels of embeds)
func (sig Signature) Unwrap() SignatureInner {
	pk := sig.SignatureInner
	for wrap, ok := pk.(Signature); ok; wrap, ok = pk.(Signature) {
		pk = wrap.SignatureInner
	}
	return pk
}

func (sig Signature) Empty() bool {
	return sig.SignatureInner == nil || sig.IsZero()
}

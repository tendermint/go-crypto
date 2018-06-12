package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type keyData struct {
	priv string
	pub  string
	addr string
}

var secpDataTable = []keyData{
	{
		priv: "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
		pub:  "02950e1cdfcb133d6024109fd489f734eeb4502418e538c28481f22bce276f248c",
		addr: "1CKZ9Nx4zgds8tU7nJHotKSDr4a9bYJCa3",
	},
}

func TestPubKeySecp256k1Address(t *testing.T) {
	for _, d := range secpDataTable {
		privB, _ := hex.DecodeString(d.priv)
		pubB, _ := hex.DecodeString(d.pub)
		addrBbz, _, _ := base58.CheckDecode(d.addr)
		addrB := Address(addrBbz)

		var priv PrivKeySecp256k1
		copy(priv[:], privB)

		pubKey := priv.PubKey()
		pubT, _ := pubKey.(PubKeySecp256k1)
		pub := pubT[:]
		addr := pubKey.Address()

		assert.Equal(t, pub, pubB, "Expected pub keys to match")
		assert.Equal(t, addr, addrB, "Expected addresses to match")
	}
}

func TestPubKeyInvalidDataProperReturnsEmpty(t *testing.T) {
	pk, err := PubKeyFromBytes([]byte("foo"))
	require.NotNil(t, err, "expecting a non-nil error")
	require.Nil(t, pk, "expecting an empty public key on error")
}

func TestAuthenticationBLS381Kos(t *testing.T) {
	for i := 0; i < 10; i++ {
		priv := GenPrivKeyBLS381KOS()
		pub, _ := priv.PubKey()
		pubKos := pub.(PubKeyBLS381KOS)
		require.True(t, pubKos.Authenticate(), "BLS381KOS key failed authentication")
	}
}

func TestBLS381KOSNotEqualOther(t *testing.T) {
	for i := 0; i < 10; i++ {
		privA := GenPrivKeyBLS381KOS()
		pubA, _ := privA.PubKey()
		privB := GenPrivKeyEd25519()
		pubB, _ := privB.PubKey()
		require.False(t, pubA.Equals(pubB), "BLS381KOS should not equal an Ed25519 key")
		privC := GenPrivKeySecp256k1()
		pubC, _ := privC.PubKey()
		require.False(t, pubA.Equals(pubC), "BLS381KOS should not equal a Secp256k1 key")
	}
}

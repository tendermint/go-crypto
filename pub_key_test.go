package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type keyData struct {
	priv       string
	pub        string
	addr       string
	bech32addr string
	bech32pub  string
}

var secpDataTable = []keyData{
	{
		priv:       "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
		pub:        "e6136ac202950e1cdfcb133d6024109fd489f734eeb4502418e538c28481f22bce276f248c",
		bech32addr: "csmsaddr:cklnrf3gj4ddtx5uvpchf3r8qzfdmgc2pcm9kknzqwc3th",
		bech32pub:  "csmspub:ucfk4sszj58peh7tzv7kqfqsnl2gnae5a669qfqcu5uv9pyp7g4uufm0yjxqpj95k8",
	},
}

func TestPubKeySecp256k1Address(t *testing.T) {
	for _, d := range secpDataTable {
		privB, _ := hex.DecodeString(d.priv)
		pubB, _ := hex.DecodeString(d.pub)
		addrDecoded := Address{}
		err := addrDecoded.FromString(d.bech32addr)
		if err != nil {
			t.Fatal(err)
		}
		var priv PrivKeySecp256k1
		copy(priv[:], privB)

		pubT := priv.PubKey().(PubKeySecp256k1)
		pubT.humanReadable = "csmspub"
		pubDeserialized := priv.PubKey().(PubKeySecp256k1)
		err = pubDeserialized.FromString(d.bech32pub)
		if err != nil {
			t.Fatal(err)
		}

		pub := pubT.Bytes()

		addr := priv.PubKey().Address()
		assert.Equal(t, pubT.String(), d.bech32pub)
		assert.Equal(t, pubT, pubDeserialized)
		assert.Equal(t, addr.String(), d.bech32addr)
		assert.Equal(t, addr.HexBytes, addrDecoded.HexBytes)
		assert.Equal(t, pub, pubB, "Expected pub keys to match")
	}
}

var ed25519DataTable = []keyData{
	{
		priv:       "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
		pub:        "328eaf59a52d39cf0fcb8e9fd431788c7731731400500b7f3c011463f8d55d3ffd8aeba1",
		bech32addr: "csmsaddr:cklnrf3gqh9lwgjh7e56u5k9tl6l7jqz5h42c3smqsdl70",
		bech32pub:  "csmspub:x2827kd995uu7r7t360agvtc33mnzuc5qpgqkleuqy2x87x4t5llmzht5yn5j4az",
	},
}

func TestPubKeyEd25519Address(t *testing.T) {
	for _, d := range ed25519DataTable {
		privB, _ := hex.DecodeString(d.priv)
		pubB, _ := hex.DecodeString(d.pub)
		addrDecoded := Address{}
		err := addrDecoded.FromString(d.bech32addr)
		if err != nil {
			t.Fatal(err)
		}
		var priv PrivKeyEd25519
		copy(priv[:], privB)

		pubT := priv.PubKey().(PubKeyEd25519)
		pubT.humanReadable = "csmspub"
		pubDeserialized := priv.PubKey().(PubKeyEd25519)
		err = pubDeserialized.FromString(d.bech32pub)
		if err != nil {
			t.Fatal(err)
		}

		pub := pubT.Bytes()

		addr := priv.PubKey().Address()
		assert.Equal(t, pubT.String(), d.bech32pub)
		assert.Equal(t, pubT, pubDeserialized)
		assert.Equal(t, addr.String(), d.bech32addr)
		assert.Equal(t, addr.HexBytes, addrDecoded.HexBytes)
		assert.Equal(t, pub, pubB, "Expected pub keys to match")
	}
}

func TestPubKeyInvalidDataProperReturnsEmpty(t *testing.T) {
	pk, err := PubKeyFromBytes([]byte("foo"))
	require.NotNil(t, err, "expecting a non-nil error")
	require.Nil(t, pk, "expecting an empty public key on error")
}

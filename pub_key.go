package crypto

import (
	"bytes"
	"crypto/sha256"
	"strings"

	"github.com/cosmos/bech32cosmos/go"

	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/tendermint/ed25519"
	"github.com/tendermint/ed25519/extra25519"
	cmn "github.com/tendermint/tmlibs/common"
	"golang.org/x/crypto/ripemd160"
)

// An address is a []byte, but hex-encoded even in JSON.
// []byte leaves us the option to change the address length.
// Use an alias so Unmarshal methods (with ptr receivers) are available too.
type Address struct {
	cmn.HexBytes
	humanReadable string
}

func (a *Address) UnmarshalJSON(data []byte) error {
	readable, deserialized, err := bech32cosmos.Decode(string(data))
	if err != nil {
		return err
	}
	a.humanReadable = readable

	err = cdc.UnmarshalBinary(deserialized, a)
	if err != nil {
		return err
	}
	return nil
}

func (a *Address) MarshalJSON() ([]byte, error) {
	marshaled, err := cdc.MarshalBinary(a)
	if err != nil {
		return nil, err
	}
	conv, err := bech32cosmos.ConvertBits(marshaled, 8, 5, true)

	readable := "csvsaddr"
	if a.humanReadable != "" {
		readable = a.humanReadable
	}
	bech, err := bech32cosmos.Encode(strings.ToLower(readable), conv)

	if err != nil {
		return nil, err
	}
	return []byte(bech), nil
}

func (a *Address) String() string {
	marshaled, err := cdc.MarshalBinary(a)
	if err != nil {
		panic("go-wire err:" + err.Error())
	}
	conv, err := bech32cosmos.ConvertBits(marshaled, 8, 5, true)

	readable := "csmsaddr"
	if a.humanReadable != "" {
		readable = a.humanReadable
	}
	bech, err := bech32cosmos.Encode(strings.ToLower(readable), conv)

	if err != nil {
		panic("bech32cosmos err:" + err.Error())
	}
	return bech
}

func (a *Address) FromString(str string) error {
	readable, deserialized, err := bech32cosmos.Decode(str)
	if err != nil {
		return err
	}

	a.humanReadable = readable

	deserialized, err = bech32cosmos.ConvertBits(deserialized, 5, 8, false)

	err = cdc.UnmarshalBinary(deserialized, a)

	if err != nil {
		return err
	}

	if err != nil {
		return err
	}
	return nil
}

func PubKeyFromBytes(pubKeyBytes []byte) (pubKey PubKey, err error) {
	err = cdc.UnmarshalBinary(pubKeyBytes, &pubKey)
	return
}

//----------------------------------------

type PubKey interface {
	Address() Address
	Bytes() []byte
	VerifyBytes(msg []byte, sig Signature) bool
	Equals(PubKey) bool
	VerifyReadable(readable string) bool
}

//-------------------------------------

var _ PubKey = PubKeyEd25519{}

// Implements PubKeyInner
type PubKeyEd25519 struct {
	Data          [32]byte
	humanReadable string
}

func (pubKey PubKeyEd25519) Address() Address {
	// append type byte
	hasher := ripemd160.New()
	hasher.Write(pubKey.Bytes()) // does not error
	return Address{hasher.Sum(nil), ""}
}

func (pubKey PubKeyEd25519) Bytes() []byte {
	bz, err := cdc.MarshalBinary(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

func (pubKey PubKeyEd25519) VerifyBytes(msg []byte, sig_ Signature) bool {
	// make sure we use the same algorithm to sign
	sig, ok := sig_.(SignatureEd25519)
	if !ok {
		return false
	}
	pubKeyBytes := [32]byte(pubKey.Data)
	sigBytes := [64]byte(sig)
	return ed25519.Verify(&pubKeyBytes, msg, &sigBytes)
}

// For use with golang/crypto/nacl/box
// If error, returns nil.
func (pubKey PubKeyEd25519) ToCurve25519() *[32]byte {
	keyCurve25519, pubKeyBytes := new([32]byte), [32]byte(pubKey.Data)
	ok := extra25519.PublicKeyToCurve25519(keyCurve25519, &pubKeyBytes)
	if !ok {
		return nil
	}
	return keyCurve25519
}

func (pubKey PubKeyEd25519) String() string {
	marshaled, err := cdc.MarshalBinary(pubKey)
	if err != nil {
		panic(err.Error())
	}
	conv, err := bech32cosmos.ConvertBits(marshaled, 8, 5, true)

	readable := "csmspub"
	if pubKey.humanReadable != "" {
		readable = pubKey.humanReadable
	}

	bech, err := bech32cosmos.Encode(strings.ToLower(readable), conv)
	if err != nil {
		return err.Error()
	}
	return bech
}

func (pubKey *PubKeyEd25519) FromString(str string) error {
	readable, deserialized, err := bech32cosmos.Decode(str)
	if err != nil {
		return err
	}
	pubKey.humanReadable = readable
	deserialized, err = bech32cosmos.ConvertBits(deserialized, 5, 8, false)

	if err != nil {
		return err
	}

	err = cdc.UnmarshalBinary(deserialized, pubKey)

	if err != nil {
		return err
	}
	return nil
}

func (pubKey PubKeyEd25519) Equals(other PubKey) bool {
	if otherEd, ok := other.(PubKeyEd25519); ok {
		return bytes.Equal(pubKey.Data[:], otherEd.Data[:])
	} else {
		return false
	}
}

func (pubkey PubKeyEd25519) VerifyReadable(readable string) bool {
	return pubkey.humanReadable == readable
}

//-------------------------------------

var _ PubKey = PubKeySecp256k1{}

// Implements PubKey.
// Compressed pubkey (just the x-cord),
// prefixed with 0x02 or 0x03, depending on the y-cord.
type PubKeySecp256k1 struct {
	Data          [33]byte
	humanReadable string
}

// Implements Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey PubKeySecp256k1) Address() Address {
	hasherSHA256 := sha256.New()
	hasherSHA256.Write(pubKey.Bytes()) // does not error
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha) // does not error
	return Address{hasherRIPEMD160.Sum(nil), ""}
}

func (pubKey PubKeySecp256k1) Bytes() []byte {
	bz, err := cdc.MarshalBinary(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

func (pubKey PubKeySecp256k1) VerifyBytes(msg []byte, sig_ Signature) bool {
	// and assert same algorithm to sign and verify
	sig, ok := sig_.(SignatureSecp256k1)
	if !ok {
		return false
	}

	pub__, err := secp256k1.ParsePubKey(pubKey.Data[:], secp256k1.S256())
	if err != nil {
		return false
	}
	sig__, err := secp256k1.ParseDERSignature(sig[:], secp256k1.S256())
	if err != nil {
		return false
	}
	return sig__.Verify(Sha256(msg), pub__)
}

func (pubKey PubKeySecp256k1) String() string {
	marshaled, err := cdc.MarshalBinary(pubKey)
	if err != nil {
		panic(err.Error())
	}
	conv, err := bech32cosmos.ConvertBits(marshaled, 8, 5, true)

	readable := "csmspub"
	if pubKey.humanReadable != "" {
		readable = pubKey.humanReadable
	}

	bech, err := bech32cosmos.Encode(strings.ToLower(readable), conv)
	if err != nil {
		return err.Error()
	}
	return bech
}

func (pubKey *PubKeySecp256k1) FromString(str string) error {
	readable, deserialized, err := bech32cosmos.Decode(str)
	if err != nil {
		return err
	}

	pubKey.humanReadable = readable
	converted, err := bech32cosmos.ConvertBits(deserialized, 5, 8, false)

	if err != nil {
		return err
	}

	err = cdc.UnmarshalBinary(converted, pubKey)
	if err != nil {
		return err
	}
	return nil
}
func (pubKey PubKeySecp256k1) Equals(other PubKey) bool {
	if otherSecp, ok := other.(PubKeySecp256k1); ok {
		return bytes.Equal(pubKey.Bytes(), otherSecp.Bytes())
	} else {
		return false
	}
}

func (pubkey PubKeySecp256k1) VerifyReadable(readable string) bool {
	return pubkey.humanReadable == readable
}

package crypto

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/ripemd160"

	bgls "github.com/Project-Arda/bgls/bgls"
	curves "github.com/Project-Arda/bgls/curves"
	secp256k1 "github.com/btcsuite/btcd/btcec"

	cmn "github.com/tendermint/tmlibs/common"

	"github.com/tendermint/ed25519"
	"github.com/tendermint/ed25519/extra25519"
	"github.com/tendermint/go-crypto/tmhash"
)

// An address is a []byte, but hex-encoded even in JSON.
// []byte leaves us the option to change the address length.
// Use an alias so Unmarshal methods (with ptr receivers) are available too.
type Address = cmn.HexBytes

func PubKeyFromBytes(pubKeyBytes []byte) (pubKey PubKey, err error) {
	err = cdc.UnmarshalBinaryBare(pubKeyBytes, &pubKey)
	return
}

//----------------------------------------

type PubKey interface {
	Address() Address
	Bytes() []byte
	VerifyBytes(msg []byte, sig Signature) bool
	Equals(PubKey) bool
}

//-------------------------------------

var _ PubKey = PubKeyEd25519{}

// Implements PubKeyInner
type PubKeyEd25519 [32]byte

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKeyEd25519) Address() Address {
	return Address(tmhash.Sum(pubKey[:]))
}

func (pubKey PubKeyEd25519) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(pubKey)
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
	pubKeyBytes := [32]byte(pubKey)
	sigBytes := [64]byte(sig)
	return ed25519.Verify(&pubKeyBytes, msg, &sigBytes)
}

// For use with golang/crypto/nacl/box
// If error, returns nil.
func (pubKey PubKeyEd25519) ToCurve25519() *[32]byte {
	keyCurve25519, pubKeyBytes := new([32]byte), [32]byte(pubKey)
	ok := extra25519.PublicKeyToCurve25519(keyCurve25519, &pubKeyBytes)
	if !ok {
		return nil
	}
	return keyCurve25519
}

func (pubKey PubKeyEd25519) String() string {
	return fmt.Sprintf("PubKeyEd25519{%X}", pubKey[:])
}

func (pubKey PubKeyEd25519) Equals(other PubKey) bool {
	if otherEd, ok := other.(PubKeyEd25519); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	} else {
		return false
	}
}

//-------------------------------------

var _ PubKey = PubKeySecp256k1{}

// Implements PubKey.
// Compressed pubkey (just the x-cord),
// prefixed with 0x02 or 0x03, depending on the y-cord.
type PubKeySecp256k1 [33]byte

// Implements Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey PubKeySecp256k1) Address() Address {
	hasherSHA256 := sha256.New()
	hasherSHA256.Write(pubKey[:]) // does not error
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha) // does not error
	return Address(hasherRIPEMD160.Sum(nil))
}

func (pubKey PubKeySecp256k1) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(pubKey)
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

	pub__, err := secp256k1.ParsePubKey(pubKey[:], secp256k1.S256())
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
	return fmt.Sprintf("PubKeySecp256k1{%X}", pubKey[:])
}

func (pubKey PubKeySecp256k1) Equals(other PubKey) bool {
	if otherSecp, ok := other.(PubKeySecp256k1); ok {
		return bytes.Equal(pubKey[:], otherSecp[:])
	} else {
		return false
	}
}

var _ PubKey = PubKeyBLS381KOS{}
var _ KOSPubKey = PubKeyBLS381KOS{}

// KOSPubKey defines an interface for Knowledge of Secret based BLS keys
type KOSPubKey interface {
	Authenticate() bool
}

// PubKeyBLS381KOS holds pubkey and KOS authentication as bytes
type PubKeyBLS381KOS [144]byte

// Address returns the 160bit hash of the public key
func (pubKey PubKeyBLS381KOS) Address() Address {
	hasher := ripemd160.New()
	hasher.Write(pubKey.Bytes()) // does not error
	return Address(hasher.Sum(nil))
}

// Bytes returns the amino encoded public key
func (pubKey PubKeyBLS381KOS) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

// VerifyBytes verifies the provided signature on the message
func (pubKey PubKeyBLS381KOS) VerifyBytes(msg []byte, sig Signature) bool {
	sigg := sig.(SignatureBLS381KOS)
	sigp, _ := curves.Bls12.UnmarshalG1(sigg[:])
	keyp, _ := curves.Bls12.UnmarshalG2(pubKey[48:])
	return bgls.KoskVerifySingleSignature(curves.Bls12, sigp, keyp, msg)
}

// String returns a string representation of the bytes of the public key
func (pubKey PubKeyBLS381KOS) String() string {
	return fmt.Sprintf("PubKeyBLS381KOS{%X}", pubKey[:])
}

// Equals checks for type and byte equality between two public keys
func (pubKey PubKeyBLS381KOS) Equals(other PubKey) bool {
	if otherBls, ok := other.(PubKeyBLS381KOS); ok {
		return bytes.Equal(pubKey[:], otherBls[:])
	}
	return false
}

// Authenticate checks that this public key includes a proof of knowledge of secret
// Needed to counteract rouge key attacks on BLS
func (pubKey PubKeyBLS381KOS) Authenticate() bool {
	auth, _ := curves.Bls12.UnmarshalG1(pubKey[:48])
	pub, _ := curves.Bls12.UnmarshalG2(pubKey[48:])
	return bgls.CheckAuthentication(curves.Bls12, pub, auth)
}

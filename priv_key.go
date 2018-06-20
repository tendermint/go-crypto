package crypto

import (
	"crypto/subtle"

	bgls "github.com/Project-Arda/bgls/bgls"
	curves "github.com/Project-Arda/bgls/curves"
	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/tendermint/ed25519"
	"github.com/tendermint/ed25519/extra25519"
	"math/big"
)

func PrivKeyFromBytes(privKeyBytes []byte) (privKey PrivKey, err error) {
	err = cdc.UnmarshalBinaryBare(privKeyBytes, &privKey)
	return
}

//----------------------------------------

type PrivKey interface {
	Bytes() []byte
	Sign(msg []byte) (Signature, error)
	PubKey() PubKey
	Equals(PrivKey) bool
}

//-------------------------------------

var _ PrivKey = PrivKeyEd25519{}

// Implements PrivKey
type PrivKeyEd25519 [64]byte

func (privKey PrivKeyEd25519) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(privKey)
}

func (privKey PrivKeyEd25519) Sign(msg []byte) (Signature, error) {
	privKeyBytes := [64]byte(privKey)
	signatureBytes := ed25519.Sign(&privKeyBytes, msg)
	return SignatureEd25519(*signatureBytes), nil
}

func (privKey PrivKeyEd25519) PubKey() PubKey {
	privKeyBytes := [64]byte(privKey)
	pubBytes := *ed25519.MakePublicKey(&privKeyBytes)
	return PubKeyEd25519(pubBytes)
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKeyEd25519) Equals(other PrivKey) bool {
	if otherEd, ok := other.(PrivKeyEd25519); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherEd[:]) == 1
	} else {
		return false
	}
}

func (privKey PrivKeyEd25519) ToCurve25519() *[32]byte {
	keyCurve25519 := new([32]byte)
	privKeyBytes := [64]byte(privKey)
	extra25519.PrivateKeyToCurve25519(keyCurve25519, &privKeyBytes)
	return keyCurve25519
}

// Deterministically generates new priv-key bytes from key.
func (privKey PrivKeyEd25519) Generate(index int) PrivKeyEd25519 {
	bz, err := cdc.MarshalBinaryBare(struct {
		PrivKey [64]byte
		Index   int
	}{privKey, index})
	if err != nil {
		panic(err)
	}
	newBytes := Sha256(bz)
	newKey := new([64]byte)
	copy(newKey[:32], newBytes)
	ed25519.MakePublicKey(newKey)
	return PrivKeyEd25519(*newKey)
}

func GenPrivKeyEd25519() PrivKeyEd25519 {
	privKeyBytes := new([64]byte)
	copy(privKeyBytes[:32], CRandBytes(32))
	ed25519.MakePublicKey(privKeyBytes)
	return PrivKeyEd25519(*privKeyBytes)
}

// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyEd25519FromSecret(secret []byte) PrivKeyEd25519 {
	privKey32 := Sha256(secret) // Not Ripemd160 because we want 32 bytes.
	privKeyBytes := new([64]byte)
	copy(privKeyBytes[:32], privKey32)
	ed25519.MakePublicKey(privKeyBytes)
	return PrivKeyEd25519(*privKeyBytes)
}

//-------------------------------------

var _ PrivKey = PrivKeySecp256k1{}

// Implements PrivKey
type PrivKeySecp256k1 [32]byte

func (privKey PrivKeySecp256k1) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(privKey)
}

func (privKey PrivKeySecp256k1) Sign(msg []byte) (Signature, error) {
	priv__, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	sig__, err := priv__.Sign(Sha256(msg))
	if err != nil {
		return nil, err
	}
	return SignatureSecp256k1(sig__.Serialize()), nil
}

func (privKey PrivKeySecp256k1) PubKey() PubKey {
	_, pub__ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	var pub PubKeySecp256k1
	copy(pub[:], pub__.SerializeCompressed())
	return pub
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKeySecp256k1) Equals(other PrivKey) bool {
	if otherSecp, ok := other.(PrivKeySecp256k1); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherSecp[:]) == 1
	} else {
		return false
	}
}

/*
// Deterministically generates new priv-key bytes from key.
func (key PrivKeySecp256k1) Generate(index int) PrivKeySecp256k1 {
	newBytes := cdc.BinarySha256(struct {
		PrivKey [64]byte
		Index   int
	}{key, index})
	var newKey [64]byte
	copy(newKey[:], newBytes)
	return PrivKeySecp256k1(newKey)
}
*/

func GenPrivKeySecp256k1() PrivKeySecp256k1 {
	privKeyBytes := [32]byte{}
	copy(privKeyBytes[:], CRandBytes(32))
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKeyBytes[:])
	copy(privKeyBytes[:], priv.Serialize())
	return PrivKeySecp256k1(privKeyBytes)
}

// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeySecp256k1FromSecret(secret []byte) PrivKeySecp256k1 {
	privKey32 := Sha256(secret) // Not Ripemd160 because we want 32 bytes.
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey32)
	privKeyBytes := [32]byte{}
	copy(privKeyBytes[:], priv.Serialize())
	return PrivKeySecp256k1(privKeyBytes)
}

// PrivKeyBLS381KOS holds secret key for "Knowledge of Secret" based BLS12-381 scheme
type PrivKeyBLS381KOS [32]byte

// Bytes returns animo encoded private key
func (privKey PrivKeyBLS381KOS) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(privKey)
	if err != nil {
		panic(err)
	}
	return bz
}

// Sign generates a BLS signature on the message
func (privKey PrivKeyBLS381KOS) Sign(msg []byte) (Signature, error) {
	sk := new(big.Int)
	sk.SetBytes(privKey[:])
	sigma := bgls.KoskSign(curves.Bls12, sk, msg)
	var sig [48]byte
	sgbz := sigma.Marshal()
	copy(sig[(48-len(sgbz)):], sgbz)
	return SignatureBLS381KOS(sig), nil
}

// PubKey generates an authenticated public key, including proof of knowledge of secret
func (privKey PrivKeyBLS381KOS) PubKey() PubKey {
	sk := new(big.Int)
	sk.SetBytes(privKey[:])
	pub := bgls.LoadPublicKey(curves.Bls12, sk)
	auth := bgls.Authenticate(curves.Bls12, sk)
	var pbz [144]byte
	copy(pbz[:48], auth.Marshal())
	copy(pbz[48:], pub.Marshal())
	return PubKeyBLS381KOS(pbz)
}

// Equals checks equality of secret key
func (privKey PrivKeyBLS381KOS) Equals(other PrivKey) bool {
	if otherBls, ok := other.(PrivKeyBLS381KOS); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherBls[:]) == 1
	}
	return false
}

// GenPrivKeyBLS381KOS generates a random secret key
func GenPrivKeyBLS381KOS() PrivKeyBLS381KOS {
	return GenPrivKeyBLS381KOSFromSecret(CRandBytes(32))
}

// GenPrivKeyBLS381KOSFromSecret generates a secret key from a byte array
func GenPrivKeyBLS381KOSFromSecret(secret []byte) PrivKeyBLS381KOS {
	sk := new(big.Int).SetBytes(secret)
	sk.Mod(sk, curves.Bls12.GetG1Order())
	skb := sk.Bytes()
	privKeyBytes := [32]byte{}
	copy(privKeyBytes[(32-len(skb)):], skb)
	return PrivKeyBLS381KOS(privKeyBytes)
}

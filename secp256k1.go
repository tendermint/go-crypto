package crypto

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/ripemd160"

	secp256k1 "github.com/btcsuite/btcd/btcec"
	cmn "github.com/tendermint/go-common"
	data "github.com/tendermint/go-data"
)

func init() {
	privKeyMapper.RegisterImplementation(PrivKeySecp256k1{}, NameSecp256k1, TypeSecp256k1)
	pubKeyMapper.RegisterImplementation(PubKeySecp256k1{}, NameSecp256k1, TypeSecp256k1)
	sigMapper.RegisterImplementation(SignatureSecp256k1{}, NameSecp256k1, TypeSecp256k1)
}

//-------------------------------------

var _ PrivKeyInner = PrivKeySecp256k1{}

// Implements PrivKey
type PrivKeySecp256k1 [32]byte

func (privKey PrivKeySecp256k1) AssertIsPrivKeyInner() {}

func (privKey PrivKeySecp256k1) Sign(msg []byte) Signature {
	priv__, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	sig__, err := priv__.Sign(Sha256(msg))
	if err != nil {
		cmn.PanicSanity(err)
	}
	return SignatureSecp256k1(sig__.Serialize()).Wrap()
}

func (privKey PrivKeySecp256k1) PubKey() PubKey {
	_, pub__ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	var pub PubKeySecp256k1
	copy(pub[:], pub__.SerializeCompressed())
	return pub.Wrap()
}

func (privKey PrivKeySecp256k1) Equals(other PrivKey) bool {
	if otherSecp, ok := other.Unwrap().(PrivKeySecp256k1); ok {
		return bytes.Equal(privKey[:], otherSecp[:])
	} else {
		return false
	}
}

func (p PrivKeySecp256k1) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(p[:])
}

func (p *PrivKeySecp256k1) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	copy(p[:], ref)
	return err
}

func (privKey PrivKeySecp256k1) String() string {
	return cmn.Fmt("PrivKeySecp256k1{*****}")
}

func (privKey PrivKeySecp256k1) Wrap() PrivKey {
	return PrivKey{privKey}
}

/*
// Deterministically generates new priv-key bytes from key.
func (key PrivKeySecp256k1) Generate(index int) PrivKeySecp256k1 {
  newBytes := wire.BinarySha256(struct {
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

//-------------------------------------

var _ PubKeyInner = PubKeySecp256k1{}

// Implements PubKey.
// Compressed pubkey (just the x-cord),
// prefixed with 0x02 or 0x03, depending on the y-cord.
type PubKeySecp256k1 [33]byte

func (pubKey PubKeySecp256k1) AssertIsPubKeyInner() {}

// Implements Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey PubKeySecp256k1) Address() []byte {
	hasherSHA256 := sha256.New()
	hasherSHA256.Write(pubKey[:]) // does not error
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha) // does not error
	return hasherRIPEMD160.Sum(nil)
}

func (pubKey PubKeySecp256k1) VerifyBytes(msg []byte, sig_ Signature) bool {
	// and assert same algorithm to sign and verify
	sig, ok := sig_.Unwrap().(SignatureSecp256k1)
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

func (p PubKeySecp256k1) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(p[:])
}

func (p *PubKeySecp256k1) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	copy(p[:], ref)
	return err
}

func (pubKey PubKeySecp256k1) String() string {
	return cmn.Fmt("PubKeySecp256k1{%X}", pubKey[:])
}

// Must return the full bytes in hex.
// Used for map keying, etc.
func (pubKey PubKeySecp256k1) KeyString() string {
	return cmn.Fmt("%X", pubKey[:])
}

func (pubKey PubKeySecp256k1) Equals(other PubKey) bool {
	if otherSecp, ok := other.Unwrap().(PubKeySecp256k1); ok {
		return bytes.Equal(pubKey[:], otherSecp[:])
	} else {
		return false
	}
}

func (pubKey PubKeySecp256k1) Wrap() PubKey {
	return PubKey{pubKey}
}

//-------------------------------------

var _ SignatureInner = SignatureSecp256k1{}

// Implements Signature
type SignatureSecp256k1 []byte

func (sig SignatureSecp256k1) AssertIsSignatureInner() {}

func (sig SignatureSecp256k1) IsZero() bool { return len(sig) == 0 }

func (sig SignatureSecp256k1) String() string { return fmt.Sprintf("/%X.../", cmn.Fingerprint(sig[:])) }

func (sig SignatureSecp256k1) Equals(other Signature) bool {
	if otherEd, ok := other.Unwrap().(SignatureSecp256k1); ok {
		return bytes.Equal(sig[:], otherEd[:])
	} else {
		return false
	}
}
func (sig SignatureSecp256k1) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(sig)
}

func (sig *SignatureSecp256k1) UnmarshalJSON(enc []byte) error {
	return data.Encoder.Unmarshal((*[]byte)(sig), enc)
}

func (sig SignatureSecp256k1) Wrap() Signature {
	return Signature{sig}
}

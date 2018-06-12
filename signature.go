package crypto

import (
	"fmt"

	"crypto/subtle"
	"math/big"

	bgls "github.com/Project-Arda/bgls/bgls"
	curves "github.com/Project-Arda/bgls/curves"
	. "github.com/tendermint/tmlibs/common"
)

func SignatureFromBytes(pubKeyBytes []byte) (pubKey Signature, err error) {
	err = cdc.UnmarshalBinaryBare(pubKeyBytes, &pubKey)
	return
}

//----------------------------------------

type Signature interface {
	Bytes() []byte
	IsZero() bool
	Equals(Signature) bool
}

//-------------------------------------

var _ Signature = SignatureEd25519{}

// Implements Signature
type SignatureEd25519 [64]byte

func (sig SignatureEd25519) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(sig)
	if err != nil {
		panic(err)
	}
	return bz
}

func (sig SignatureEd25519) IsZero() bool { return len(sig) == 0 }

func (sig SignatureEd25519) String() string { return fmt.Sprintf("/%X.../", Fingerprint(sig[:])) }

func (sig SignatureEd25519) Equals(other Signature) bool {
	if otherEd, ok := other.(SignatureEd25519); ok {
		return subtle.ConstantTimeCompare(sig[:], otherEd[:]) == 1
	} else {
		return false
	}
}

func SignatureEd25519FromBytes(data []byte) Signature {
	var sig SignatureEd25519
	copy(sig[:], data)
	return sig
}

//-------------------------------------

var _ Signature = SignatureSecp256k1{}

// Implements Signature
type SignatureSecp256k1 []byte

func (sig SignatureSecp256k1) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(sig)
	if err != nil {
		panic(err)
	}
	return bz
}

func (sig SignatureSecp256k1) IsZero() bool { return len(sig) == 0 }

func (sig SignatureSecp256k1) String() string { return fmt.Sprintf("/%X.../", Fingerprint(sig[:])) }

func (sig SignatureSecp256k1) Equals(other Signature) bool {
	if otherSecp, ok := other.(SignatureSecp256k1); ok {
		return subtle.ConstantTimeCompare(sig[:], otherSecp[:]) == 1
	} else {
		return false
	}
}

func SignatureSecp256k1FromBytes(data []byte) Signature {
	sig := make(SignatureSecp256k1, len(data))
	copy(sig[:], data)
	return sig
}

// AggregatableSignature defines the interface for signatures which support aggregation and multisignature verification
type AggregatableSignature interface {
	Aggregate([]AggregatableSignature) (AggregatableSignature, bool)
	Scale(int64) (AggregatableSignature, bool)
	VerifyBytesWithMultiplicity([]PubKey, []int64, []byte) bool
}

var _ Signature = SignatureBLS381KOS{}
var _ AggregatableSignature = SignatureBLS381KOS{}

// SignatureBLS381KOS holds a BLS381 signature
type SignatureBLS381KOS [48]byte

// Bytes returns the amino encoding of the signature
func (sig SignatureBLS381KOS) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(sig)
	if err != nil {
		panic(err)
	}
	return bz
}

// IsZero checks if the signature object is empty
func (sig SignatureBLS381KOS) IsZero() bool { return len(sig) == 0 }

// String returns a printable representation of the signature
func (sig SignatureBLS381KOS) String() string { return fmt.Sprintf("/%X.../", Fingerprint(sig[:])) }

// Equals checks type and byte equality between signatures
func (sig SignatureBLS381KOS) Equals(other Signature) bool {
	if otherBls, ok := other.(SignatureBLS381KOS); ok {
		return subtle.ConstantTimeCompare(sig[:], otherBls[:]) == 1
	}
	return false
}

// Aggregate takes a set of signatures on the same message, and returns a single signature
// Can be used to compress multsignature schemes
func (sig SignatureBLS381KOS) Aggregate(sigs []AggregatableSignature) (AggregatableSignature, bool) {
	sgs := make([]curves.Point, len(sigs))
	for i := 0; i < len(sigs); i++ {
		s, ok := sigs[i].(SignatureBLS381KOS)
		if !ok {
			return SignatureBLS381KOS{}, false
		}
		sp, ok := curves.Bls12.UnmarshalG1(s[:])
		if ok != true {
			return SignatureBLS381KOS{}, false
		}
		sgs[i] = sp

	}
	var sbz [48]byte
	bz := bgls.AggregateSignatures(sgs).Marshal()
	copy(sbz[(48-len(bz)):], bz)
	return SignatureBLS381KOS(sbz), true
}

// Scale takes a single signature and scales it by an integer
// Equivalent to adding n copies of the signature to itself
func (sig SignatureBLS381KOS) Scale(scalar int64) (AggregatableSignature, bool) {
	s, ok := curves.Bls12.UnmarshalG1(sig[:])
	if ok != true {
		return SignatureBLS381KOS{}, false
	}
	bz := s.Mul(big.NewInt(scalar)).Marshal()
	var ssbz [48]byte
	copy(ssbz[(48-len(bz)):], bz)
	return SignatureBLS381KOS(ssbz), true
}

// VerifyBytesWithMultiplicity verifies that a sequence of keys signed a message
// with multiplicity to allow for overlapping aggregation
func (sig SignatureBLS381KOS) VerifyBytesWithMultiplicity(keys []PubKey, multiplicity []int64, msg []byte) bool {
	pks := make([]curves.Point, len(keys))
	for i := 0; i < len(keys); i++ {
		keyBLS381KOS := keys[i].(PubKeyBLS381KOS)
		k, suc := curves.Bls12.UnmarshalG2(keyBLS381KOS[48:])
		if suc != true {
			return false
		}
		pks[i] = k
	}
	sigp, suc := curves.Bls12.UnmarshalG1(sig[:])
	return suc && bgls.KoskVerifyMultiSignatureWithMultiplicity(curves.Bls12, sigp, pks, multiplicity, msg)
}

package cryptostore

import (
	"fmt"

	"github.com/pkg/errors"
	crypto "github.com/tendermint/go-crypto"
	// 	"github.com/tendermint/go-crypto/nano"
)

var (
	// GenEd25519 produces Ed25519 private keys
	GenEd25519 Generator = GenFunc(genEd25519)
	// GenSecp256k1 produces Secp256k1 private keys
	GenSecp256k1 Generator = GenFunc(genSecp256)
	// GenLedgerEd25519 used Ed25519 keys stored on nano ledger s with cosmos app
	GenLedgerEd25519 Generator = GenFunc(genLedgerEd25519)
)

// Generator determines the type of private key the keystore creates
type Generator interface {
	Generate(secret []byte) (crypto.PrivKey, error)
}

// GenFunc is a helper to transform a function into a Generator
type GenFunc func(secret []byte) (crypto.PrivKey, error)

func (f GenFunc) Generate(secret []byte) (crypto.PrivKey, error) {
	return f(secret)
}

//---------------------------------------------------------------

func genEd25519(secret []byte) (crypto.PrivKey, error) {
	key := crypto.GenPrivKeyEd25519FromSecret(secret).Wrap()
	return key, nil
}

func genSecp256(secret []byte) (crypto.PrivKey, error) {
	key := crypto.GenPrivKeySecp256k1FromSecret(secret).Wrap()
	return key, nil
}

// secret is completely ignored for the ledger...
// just for interface compatibility
func genLedgerEd25519(secret []byte) (crypto.PrivKey, error) {
	return crypto.PrivKey{}, fmt.Errorf("temporarily unsupported") // nano.NewPrivKeyLedgerEd25519Ed25519()
}

func getGeneratorByName(algo string) (Generator, error) {
	switch algo {
	case crypto.NameEd25519:
		return GenEd25519, nil
	case crypto.NameSecp256k1:
		return GenSecp256k1, nil
		//	case nano.NameLedgerEd25519:
		//		return GenLedgerEd25519
	default:
		return nil, errors.Errorf("Cannot generate keys for algorithm: %s", algo)
	}
}

func getGeneratorByType(typ byte) (Generator, error) {
	switch typ {
	case crypto.TypeEd25519:
		return GenEd25519, nil
	case crypto.TypeSecp256k1:
		return GenSecp256k1, nil
		//	case nano.TypeLedgerEd25519:
		//		return GenLedgerEd25519
	default:
		return nil, errors.Errorf("Cannot generate keys for algorithm: %d", typ)
	}
}

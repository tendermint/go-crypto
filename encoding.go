package crypto

import (
	"bytes"

	wire "github.com/tendermint/go-wire"
)

func marshalJSON(o interface{}) ([]byte, error) {
	w, n, err := new(bytes.Buffer), new(int), new(error)
	wire.WriteJSON(o, w, n, err)
	if *err != nil {
		return nil, *err
	}
	return w.Bytes(), nil
}

func unmarshalJSON(data []byte, o interface{}) error {
	return wire.ReadJSONBytes(data, o)
}

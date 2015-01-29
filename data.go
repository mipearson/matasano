package matasano

import (
	"encoding/base64"
	"encoding/hex"
)

type Base64 []byte
type Hex []byte

func (h Hex) Decode() []byte {
	dst := make([]byte, hex.DecodedLen(len(h)))
	_, err := hex.Decode(dst, h)
	checkerr(err)

	return dst
}

func ToHex(src []byte) Hex {
	dst := make(Hex, hex.EncodedLen(len(src)))
	_ = hex.Encode(dst, src)
	return dst
}

func ToBase64(src []byte) Base64 {
	enc := base64.StdEncoding
	dst := make(Base64, enc.EncodedLen(len(src)))
	enc.Encode(dst, src)
	return dst
}

func (b Base64) Decode() []byte {
	enc := base64.StdEncoding
	dst := make([]byte, enc.DecodedLen(len(b)))
	enc.Decode(dst, b)
	return dst
}

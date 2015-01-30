package matasano

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
)

type Base64 []byte
type Hex []byte

var WhitespaceRegexp = regexp.MustCompile("\\s+")

func (h Hex) Decode() []byte {
	dst := make([]byte, hex.DecodedLen(len(h)))
	len, err := hex.Decode(dst, h)
	checkerr(err)

	return dst[:len]
}

func ToHex(src []byte) Hex {
	dst := make(Hex, hex.EncodedLen(len(src)))
	_ = hex.Encode(dst, src)
	return dst
}

func ToBase64(src []byte) Base64 {
	dst := make(Base64, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dst, src)
	return dst
}

func (b Base64) Decode() []byte {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	len, err := base64.StdEncoding.Decode(dst, b)
	checkerr(err)
	return dst[:len]
}

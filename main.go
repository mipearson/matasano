package main

import "log"
import "encoding/hex"
import "encoding/base64"

func checkerr(err error) {
	if err != nil {
		log.Fatalf("Error encountered: %q", err)
	}
}

func hexDecode(src []byte) []byte {
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	checkerr(err)

	return dst
}

func hexEncode(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	_ = hex.Encode(dst, src)
	return dst
}

func HexToBase64(src []byte) []byte {

	raw := hexDecode(src)
	enc := base64.StdEncoding
	dst := make([]byte, enc.EncodedLen(len(raw)))
	enc.Encode(dst, raw)
	return dst
}

func XorHex(a []byte, b []byte) []byte {
	ab := hexDecode(a)
	bb := hexDecode(b)

	c := make([]byte, len(ab))
	for i := 0; i < len(c); i++ {
		c[i] = ab[i] ^ bb[i]
	}
	return hexEncode(c)
}

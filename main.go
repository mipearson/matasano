package main

import "log"
import "encoding/hex"
import "encoding/base64"

func checkerr(err error) {
	if err != nil {
		log.Fatalf("Error encountered: %q", err)
	}
}
func HexToBase64(src []byte) []byte {
	raw := make([]byte, hex.DecodedLen(len(src)))

	_, err := hex.Decode(raw, src)
	checkerr(err)

	enc := base64.StdEncoding
	dst := make([]byte, enc.EncodedLen(len(raw)))
	enc.Encode(dst, raw)
	return dst
}

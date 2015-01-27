package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"unicode/utf8"
)

const Frequencies = "ZQXJKVBWPYGUMCFLDHSIRNOATE"
const Disqualifiers = "\x00\x01\x02\x03\x04\x05\x06\x07"

type Candidate struct {
	plaintext []byte
	cipher    []byte
}

type byScore []Candidate

func (a byScore) Len() int           { return len(a) }
func (a byScore) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byScore) Less(i, j int) bool { return a[i].Score() < a[j].Score() }

func checkerr(err error) {
	if err != nil {
		// log.Fatalln(err)
		panic(err)
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

	c := Xor(ab, bb)
	return hexEncode(c)
}

func Xor(ab []byte, bb []byte) []byte {
	c := make([]byte, len(ab))
	for i := 0; i < len(c); i++ {
		c[i] = ab[i] ^ bb[i]
	}
	return c
}

func (c *Candidate) Score() int {
	if !utf8.Valid(c.plaintext) || bytes.IndexAny(c.plaintext, Disqualifiers) != -1 {
		return 0
	}
	score := 0
	asUpper := bytes.ToUpper(c.plaintext)
	for _, b := range asUpper {
		score += scoreOfByte(b)
	}
	return score
}

func scoreOfByte(src byte) int {
	idx := bytes.IndexByte([]byte(Frequencies), src)
	if idx == -1 {
		return 0
	} else {
		return idx
	}
}

func DecodeSimpleXorCipher(cipherHex []byte, count int) []Candidate {
	var candidates []Candidate

	cipher := hexDecode(cipherHex)
	for i := 0; i < 255; i++ {
		xor := bytes.Repeat([]byte{byte(i)}, len(cipher))
		candidate := Candidate{
			plaintext: Xor(cipher, xor),
			cipher:    []byte{byte(i)},
		}
		if candidate.Score() > 0 {
			candidates = append(candidates, candidate)
		}
	}

	sort.Sort(sort.Reverse(byScore(candidates)))
	return candidates[:count]
}

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"unicode/utf8"
)

const Frequencies = "ZQXJKVBWPYGUMCFLDHSIRNOATE"
const Disqualifiers = "\x00\x01\x02\x03\x04\x05\x06\x07"

type Candidate struct {
	plaintext []byte
	cipher    []byte
}

type Candidates []Candidate

func (a Candidates) Len() int           { return len(a) }
func (a Candidates) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Candidates) Less(i, j int) bool { return a[i].Score() < a[j].Score() }

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

func base64Encode(src []byte) []byte {
	enc := base64.StdEncoding
	dst := make([]byte, enc.EncodedLen(len(src)))
	enc.Encode(dst, src)
	return dst
}

func HexToBase64(src []byte) []byte {
	return base64Encode(hexDecode(src))
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

func DecodeSimpleXorCipher(cipherHex []byte) Candidates {
	var candidates Candidates

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
	return candidates
}

func RepeatingKeyXOR(src []byte, key []byte) []byte {
	dst := make([]byte, len(src))
	for i, b := range src {
		keyidx := i % len(key)
		dst[i] = b ^ key[keyidx]
	}
	return dst
}

func HammingDistance(a []byte, b []byte) int {
	xor := Xor(a, b)
	count := 0
	for _, b := range xor {
		for i := 0; i < 8; i++ {
			if b&(1<<uint8(i)) > 0 {
				count += 1
			}
		}
	}
	return count
}

const MinKeysize = 2
const MaxKeysize = 40
const MaxDistance = 8.0

func GuessKeysize(cipher []byte) int {
	bestDistance := MaxDistance
	bestSize := 0

	for size := MinKeysize; size <= MaxKeysize; size += 1 {
		score := ScoreKeysize(cipher, size)
		fmt.Printf("size: %d score: %f\n", size, score)
		if score < bestDistance {
			bestDistance = score
			bestSize = size
		}
	}
	return bestSize
}

func ScoreKeysize(cipher []byte, size int) float64 {
	if len(cipher) < (size * 2) {
		return MaxDistance
	}

	a := cipher[:size]
	b := cipher[size : size*2]

	return float64(HammingDistance(a, b)) / float64(size)
}

func (a Candidates) Top(count int) Candidates {
	sort.Sort(sort.Reverse(a))
	return a[:count]
}

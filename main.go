package matasano

import (
	"bytes"
	"crypto/aes"
	"sort"
	"unicode/utf8"
)

const Frequencies = "ZQXJKVBWPYGUMCFLDHSIRNOATE"
const Disqualifiers = "\x00\x01\x02\x03\x04\x05\x06\x07"

type Candidate struct {
	plaintext []byte
	key       []byte
}

type Candidates []Candidate

func (a Candidates) Len() int                  { return len(a) }
func (a Candidates) Swap(i, j int)             { a[i], a[j] = a[j], a[i] }
func (a Candidates) Less(i, j int) bool        { return a[i].Score() < a[j].Score() }
func (a KeysizeCandidates) Len() int           { return len(a) }
func (a KeysizeCandidates) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a KeysizeCandidates) Less(i, j int) bool { return a[i].Score < a[j].Score }

func checkerr(err error) {
	if err != nil {
		// log.Fatalln(err)
		panic(err)
	}
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

func DecodeSimpleXorCipher(cipher []byte) Candidates {
	var candidates Candidates

	for i := 0; i < 255; i++ {
		xor := bytes.Repeat([]byte{byte(i)}, len(cipher))
		candidate := Candidate{
			plaintext: Xor(cipher, xor),
			key:       []byte{byte(i)},
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
	if len(a) != len(b) {
		panic("len(a) != len(b)")
	}
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

type KeysizeCandidate struct {
	Score   float64
	Keysize int
}
type KeysizeCandidates []KeysizeCandidate

func GuessKeysize(cipher []byte) KeysizeCandidates {
	candidates := make(KeysizeCandidates, 0)

	for size := MinKeysize; size <= MaxKeysize; size += 1 {
		score := BlockDistance(cipher, size)
		if score != -1 {
			candidates = append(candidates, KeysizeCandidate{Score: score, Keysize: size})
		}
	}
	return candidates
}

func BlockDistance(cipher []byte, size int) float64 {
	if len(cipher) < (size * 4) {
		return -1
	}

	distance := 0
	iterations := (len(cipher) / size) - 1

	for i := 0; i < iterations; i += 1 {
		a := cipher[i*size : (i+1)*size]
		b := cipher[(i+1)*size : (i+2)*size]

		distance += HammingDistance(a, b)
	}

	return float64(distance) / float64(size) / float64(iterations)
}

func (a Candidates) Top(count int) Candidates {
	sort.Sort(sort.Reverse(a))
	return a[:count]
}

func (a KeysizeCandidates) Top(count int) KeysizeCandidates {
	sort.Sort(a)
	return a[:count]
}

func (a KeysizeCandidates) ContainsSize(size int) bool {
	for _, k := range a {
		if k.Keysize == size {
			return true
		}
	}
	return false
}

func everyNthByte(src []byte, offset int, blocksize int) []byte {
	dst := make([]byte, len(src)/blocksize)

	for i := 0; i < len(dst); i += 1 {
		dst[i] = src[i*blocksize+offset]
	}
	return dst
}

func GuessRepeatingKey(cipher []byte) Candidates {
	keysize := GuessKeysize(cipher).Top(1)[0].Keysize

	key := make([]byte, keysize)

	for i := 0; i < keysize; i++ {
		slices := everyNthByte(cipher, i, keysize)
		key[i] = DecodeSimpleXorCipher(slices).Top(1)[0].key[0]
	}
	candidate := Candidate{
		key:       key,
		plaintext: RepeatingKeyXOR(cipher, key),
	}
	return Candidates{candidate}

}

func DecryptAESECB(cipher []byte, key []byte) []byte {
	aes, err := aes.NewCipher(key)
	checkerr(err)

	dst := make([]byte, len(cipher))
	for i := 0; i < len(dst); i += aes.BlockSize() {
		aes.Decrypt(dst[i:], cipher[i:])
	}
	return dst
}

func EncryptAESECB(plaintext []byte, key []byte) []byte {
	aes, err := aes.NewCipher(key)
	checkerr(err)

	dst := make([]byte, len(plaintext))
	for i := 0; i < len(dst); i += aes.BlockSize() {
		aes.Encrypt(dst[i:], plaintext[i:])
	}
	return dst
}

func DecryptAESCBC(cipher []byte, key []byte, iv []byte) []byte {
	aes, err := aes.NewCipher(key)
	checkerr(err)

	if len(iv) != aes.BlockSize() {
		panic("aes.BlockSize != len(iv)")
	}

	dst := make([]byte, len(cipher))
	for i := 0; i < len(dst); i += aes.BlockSize() {
		til := i + aes.BlockSize()
		aes.Decrypt(dst[i:], cipher[i:])
		copy(dst[i:til], Xor(dst[i:til], iv))
		iv = cipher[i:]
	}
	return dst
}

func EncryptAESCBC(plaintext []byte, key []byte, iv []byte) []byte {
	aes, err := aes.NewCipher(key)
	checkerr(err)

	if len(iv) != aes.BlockSize() {
		panic("aes.BlockSize != len(iv)")
	}

	dst := make([]byte, len(plaintext))
	for i := 0; i < len(dst); i += aes.BlockSize() {
		til := i + aes.BlockSize()
		part := Xor(iv, plaintext[i:til])
		aes.Encrypt(dst[i:], part)
		iv = dst[i:til]
	}
	return dst
}

func DiscoverECB(cipher []byte, keysize int) bool {
	for a := 0; a < len(cipher); a += keysize {
		for b := 0; b < len(cipher); b += keysize {
			if a != b && bytes.Equal(cipher[a:a+keysize], cipher[b:b+keysize]) {
				return true
			}
		}
	}
	return false
}

func Pkcs7Padding(src []byte, blocksize int) []byte {
	more := blocksize - (len(src) % blocksize)
	dst := make([]byte, len(src)+more)
	copy(dst, src)
	for i := len(src); i < len(dst); i++ {
		dst[i] = 4
	}
	return dst
}

package main

import (
	"fmt"
	"io/ioutil"
	"testing"
)
import "bytes"

func TestHexToBase64(t *testing.T) {
	hex := []byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	base64 := []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

	got := HexToBase64(hex)
	if !bytes.Equal(got, base64) {
		t.Errorf("HexToBase64(%s) == %s, want %s", hex, got, base64)
	}
}

func TestXorHex(t *testing.T) {
	orig := []byte("1c0111001f010100061a024b53535009181c")
	xor := []byte("686974207468652062756c6c277320657965")
	expected := []byte("746865206b696420646f6e277420706c6179")

	got := XorHex(orig, xor)
	if !bytes.Equal(got, expected) {
		t.Errorf("XorHex(%s, %s) == %s, want %s", orig, xor, got, expected)
	}
}

func checkForExpectedCandidate(c Candidates, expected Candidate, debug bool) bool {
	found := false
	for _, candidate := range c {
		if debug {
			fmt.Printf("cipher: %q score: %d plaintext: %q\n", candidate.cipher, candidate.Score(), candidate.plaintext)
		}
		if bytes.Equal(candidate.plaintext, expected.plaintext) && bytes.Equal(candidate.cipher, expected.cipher) {
			found = true
		}
	}
	return found
}

func TestDecodeSimpleXorCipher(t *testing.T) {
	ciphertext := []byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	expected := Candidate{
		plaintext: []byte("Cooking MC's like a pound of bacon"),
		cipher:    []byte{'X'},
	}

	candidates := DecodeSimpleXorCipher(ciphertext).Top(5)
	if !checkForExpectedCandidate(candidates, expected, false) {
		t.Errorf("TestDecodeSimpleXorCipher could not find matching plaintext from %s", ciphertext)
	}
}

func TestFindSimpleXorCipheredString(t *testing.T) {
	file, err := ioutil.ReadFile("data/set1_challenge4.txt")
	checkerr(err)
	ciphertexts := bytes.Split(file, []byte{'\n'})

	candidates := Candidates{}
	for _, cipher := range ciphertexts {
		cipher = bytes.TrimSpace(cipher)
		candidates = append(candidates, DecodeSimpleXorCipher(cipher)...)
	}
	expected := Candidate{
		plaintext: []byte("Now that the party is jumping\n"),
		cipher:    []byte{'5'},
	}
	if !checkForExpectedCandidate(candidates.Top(5), expected, false) {
		t.Errorf("TestFindSimpleXorCipheredString could not find matching plaintext")
	}
}

func TestRepeatingKeyXor(t *testing.T) {
	plaintext := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	expected := []byte("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

	got := hexEncode(RepeatingKeyXOR(plaintext, []byte("ICE")))
	if !bytes.Equal(got, expected) {
		t.Errorf("TestRepeatingKeyXor got %q, expected %q", got, expected)
	}
}

func TestHammingDistance(t *testing.T) {
	a := []byte("this is a test")
	b := []byte("wokka wokka!!!")
	expected := 37

	got := HammingDistance(a, b)
	if got != expected {
		t.Errorf("TextHammingDistance(%q, %q): got %d, expected %d", a, b, got, expected)
	}
}

func TestGuessKeysize(t *testing.T) {
	cipher := []byte("aabb0011aabb0011aabb0011aabb0011aabb0011aabb0011aabb0011aabb0011")
	expected := 8
	got := GuessKeysize(cipher)
	if got != expected {
		t.Errorf("TestGuessKeySize: got %d, expected %d", got, expected)
	}
}

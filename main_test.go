package matasano

import (
	"fmt"
	"io/ioutil"
	"testing"
)
import "bytes"

func TestHexToBase64(t *testing.T) {
	hex := Hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	base64 := Base64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

	got := ToBase64(hex.Decode())
	if !bytes.Equal(got, base64) {
		t.Errorf("ToBase64(hex.Decode()) for %s == %s, want %s", hex, got, base64)
	}
}

func TestXor(t *testing.T) {
	orig := Hex("1c0111001f010100061a024b53535009181c")
	xor := Hex("686974207468652062756c6c277320657965")
	expected := Hex("746865206b696420646f6e277420706c6179")

	got := Xor(orig.Decode(), xor.Decode())
	if !bytes.Equal(got, expected.Decode()) {
		t.Errorf("Xor(%s, %s) == %s, want %s", orig, xor, got, expected)
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
	ciphertext := Hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	expected := Candidate{
		plaintext: []byte("Cooking MC's like a pound of bacon"),
		cipher:    []byte{'X'},
	}

	candidates := DecodeSimpleXorCipher(ciphertext.Decode()).Top(5)
	if !checkForExpectedCandidate(candidates, expected, false) {
		t.Errorf("TestDecodeSimpleXorCipher could not find matching plaintext from %s", ciphertext)
	}
}

func TestFindSimpleXorCipheredString(t *testing.T) {
	file, err := ioutil.ReadFile("data/set1_challenge4.txt")
	checkerr(err)
	ciphertexts := bytes.Split(file, []byte{'\n'})

	candidates := Candidates{}
	for _, text := range ciphertexts {
		cipher := Hex(bytes.TrimSpace(text))
		candidates = append(candidates, DecodeSimpleXorCipher(cipher.Decode())...)
	}
	expected := Candidate{
		plaintext: []byte("Now that the party is jumping\n"),
		cipher:    []byte{'5'},
	}
	if !checkForExpectedCandidate(candidates.Top(5), expected, false) {
		t.Errorf("TestFindSimpleXorCipheredString could not find matching plaintext")
	}
}

var repeatingKeyCases = []struct {
	plaintext []byte
	key       []byte
	cipher    Base64
}{
	{
		[]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"),
		[]byte("ICE"),
		Base64("CzY3JyorLmNiLC5paSojaToqPGMkIC1iPWM0PComImMkJydlJyooKy8gQwplLixlKjEkMzplPisgJ2MMaSsgKDFlKGMmMC4nKC8="),
	},
	{
		[]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"),
		[]byte("Z22qbcPASAQ&255"),
		Base64("GEdAHwsNN2F0JDwKElxTektdBEICOS90NXFXR1xWMRJTHwZDPig+Iz1DOHwVPV0SEhACKjhzNjlDXBV8elpXEBBDMWEwODxEU1k="),
	},
	{
		[]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."),
		[]byte("S3_fFjS$sAT*qC"),
		Base64("H1wtAytKOlQANDkKFSw/XC1GNQMnBBIsMV5dYzBcMRUjCSdBBzQmChAnOkM2FSUDPUNTJDhDBW9zQDoCZg48BBYoIVkcLDcTKwMrGjxWUyg6SRgnOlcqCDJKJlBTLTVIHjE2EzoSZg48SBwzMQocIjRdPkYnBjpVBiB6CiQ3c1YxDytKMkBTLD1EGC5zRToILws+CFMwIUMCYz1cLBI0HzcEFjkxWBIqJ1IrDykEc1EfLTVHEixzXz4EKRg6V1MvPVkYYyZHfwcqAyJRGjF0TwljNlJ/BSkHPksXLnRJHi0gVi4TJx59BDc0PVlRIiZHOkYvGCZWFmEwRR0sIRM2CGYYNlQBJDxPHyc2QTYSZgM9BAUuOF8BNzJHOkYwDz9NB2ExWQImc1A2CiofPgQXLjhFAyZzVipGIB80TRI1dEQELz9SfxYnGDpFBzQmBFEGK1A6FjIPJlZTMj1EBWM8UDwHIwkyUFMiIVoYJzJHPhJmBDxKUzEmRRgnNl0rSmYZJkoHYT1EUSAmXy8HZhsmTVMuMkwYIDpSfwIjGTZWBi8gChwsP182EmYLPU0eYT1OUSYgR38KJwg8VgYseg=="),
	},
}

func TestRepeatingKeyXor(t *testing.T) {
	for _, test := range repeatingKeyCases {
		got := ToBase64(RepeatingKeyXOR(test.plaintext, test.key))
		if !bytes.Equal(got, test.cipher) {
			t.Errorf("TestRepeatingKeyXor(%q, %q) got %q, expected %q", test.plaintext, test.key, got, test.cipher)
		}
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
	for _, test := range repeatingKeyCases {
		got := GuessKeysize(test.cipher.Decode()).Top(1)
		expected := len(test.key)

		if !got.ContainsSize(expected) {
			t.Errorf("TestGuessKeySize(%q): got %+v, expected one to have size %d", test.cipher, got, expected)
		}
	}
}

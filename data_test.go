package matasano

import (
	"bytes"
	"testing"
)

func TestRandBytes(t *testing.T) {
	a := RandBytes(16)
	b := RandBytes(16)

	if bytes.Equal(a, b) {
		t.Errorf("TestRandBytes(16) gave equal results on successive calls: %v", a)
	}

	if len(a) != 16 {
		t.Errorf("TestRandBytes(16) gave len of %d, expected 16", len(a))
	}
}

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

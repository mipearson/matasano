package main

import "testing"
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

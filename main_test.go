package main

import "testing"
import "reflect"

const Hex string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
const Base64 string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

func TestHexToBase64(t *testing.T) {
	got := HexToBase64([]byte(Hex))
	if !reflect.DeepEqual(got, []byte(Base64)) {
		t.Errorf("HexToBase64(%q) == %q, want %q", Hex, string(got), Base64)
	}
}

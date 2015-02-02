package set2

import (
	"bytes"
	"testing"
)

func TestDiscoverKeysize(t *testing.T) {
	got := Encrypter(RandomCBC).DiscoverKeysize()
	if got != 16 {
		t.Errorf("TestDiscoverKeysize: got %d, expected 16", got)
	}
}

func TestIsECB(t *testing.T) {
	if !Encrypter(RandomECB).IsECB(16) {
		t.Errorf("IsECB on RandomECB got false, expected true")
	}
	if Encrypter(RandomCBC).IsECB(16) {
		t.Errorf("IsECB on RandomCBC got true, expected false")
	}
}

func TestPersistentKey(t *testing.T) {
	expected := PersistentKey()
	got := PersistentKey()

	if len(got) != 16 {
		t.Errorf("TestPersistentKey: expected a key of len 16, got %d", len(got))
	}

	if !bytes.Equal(got, expected) {
		t.Errorf("TestPersistentKey: expected subsequent calls to give equal results")
	}
}

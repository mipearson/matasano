package set2

import (
	"bytes"
	"reflect"
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

func TestSet2Challenge12Decrypt(t *testing.T) {
	expected := []byte("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x04\x04\x04\x04\x04\x04")
	got := Set2Challenge12Decrypt()

	if !bytes.Equal(got, expected) {
		t.Errorf("TestSet2Challenge12Decrypt: got %q expected %q", got, expected)
	}
}

func TestDiscoveryPrefix(t *testing.T) {
	cases := []struct {
		known    []byte
		expected [][]byte
	}{
		{
			[]byte(""),
			[][]byte{[]byte("AAAAAAA"), []byte("AAAAAAA")},
		},
		{
			[]byte("HI"),
			[][]byte{[]byte("AAAAA"), []byte("AAAAAHI")},
		},
		{
			[]byte("ABCDEFJIHKL"),
			[][]byte{[]byte("AAAA"), []byte("EFJIHKL")},
		},
	}

	for _, c := range cases {
		gotPrefix, gotCandidate := discoveryPrefix(8, c.known)
		if !bytes.Equal(gotPrefix, c.expected[0]) {
			t.Errorf("TestDiscoveryPrefix(8, %q), got prefix %q expected %q", c.known, gotPrefix, c.expected[0])
		}
		if !bytes.Equal(gotCandidate, c.expected[1]) {
			t.Errorf("TestDiscoveryPrefix(8, %q), got candidate %q expected %q", c.known, gotCandidate, c.expected[1])
		}
	}
}

func TestProfileFor(t *testing.T) {
	cases := []struct {
		email    []byte
		expected Profile
	}{
		{
			[]byte("foo@bar.com"),
			Profile{"email": []byte("foo@bar.com"), "uid": []byte("10"), "role": []byte("user")},
		},
		{
			[]byte("foo@bar.com&role=admin"),
			Profile{"email": []byte("foo@bar.comroleadmin"), "uid": []byte("10"), "role": []byte("user")},
		},
	}

	for _, c := range cases {
		got := BytesToProfile(PersistentAESECBDecrypt(ProfileFor(c.email)))
		if !reflect.DeepEqual(got, c.expected) {
			t.Errorf("TestProfileFor(%q) got %v expected %v", c.email, got, c.expected)
		}
	}
}

func TestProfileIsAdmin(t *testing.T) {
	cases := []struct {
		profile  Profile
		expected bool
	}{
		{Profile{"role": []byte("user")}, false},
		{Profile{"role": []byte("admin")}, true},
	}

	for _, c := range cases {
		got := c.profile.IsAdmin()
		if got != c.expected {
			t.Errorf("TestProfileIsAdmin(%v) got %v expected %v", c.profile, got, c.expected)
		}
	}
}

func TestSet2Challenge13ForceAdminProfile(t *testing.T) {
	ciphertext := Set2Challenge13ForceAdminProfile()
	profile := BytesToProfile(PersistentAESECBDecrypt(ciphertext))

	if !profile.IsAdmin() {
		t.Errorf("TestSet2Challenge13ForceAdminProfile: expected profile %v to be admin, profile is %s", profile, PersistentAESECBDecrypt(ciphertext))
	}
}

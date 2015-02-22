package set2

import (
	"bytes"
	"fmt"
	"log"

	"github.com/mipearson/matasano"
)

type Encrypter func([]byte) []byte

func RandomECB(plaintext []byte) []byte {
	return matasano.EncryptAESECB(matasano.Pkcs7Padding(plaintext, 16), matasano.RandBytes(16))
}

func RandomCBC(plaintext []byte) []byte {
	return matasano.EncryptAESCBC(matasano.Pkcs7Padding(plaintext, 16), matasano.RandBytes(16), matasano.RandBytes(16))
}

func (e Encrypter) DiscoverKeysize() int {
	plaintext := []byte("A")
	base := len(e(plaintext))
	newlen := base
	for ; newlen == base; plaintext = append(plaintext, 'A') {
		newlen = len(e(plaintext))
	}

	return newlen - base
}

func (e Encrypter) IsECB(keysize int) bool {
	plaintext := bytes.Repeat([]byte(" "), keysize*4)
	return matasano.CipherIsECB(e(plaintext), 16)
}

var CachedPersistentKey []byte

func PersistentKey() []byte {
	if len(CachedPersistentKey) == 0 {
		CachedPersistentKey = matasano.RandBytes(16)
	}

	return CachedPersistentKey
}

func PersistentAESECBEncrypt(plaintext []byte) []byte {
	return matasano.EncryptAESECB(matasano.Pkcs7Padding(plaintext, len(PersistentKey())), PersistentKey())
}

func PersistentAESECBDecrypt(ciphertext []byte) []byte {
	return matasano.StripPadding(matasano.DecryptAESECB(ciphertext, PersistentKey()))
}

func Set2Challenge12Crypt(plaintext []byte) []byte {
	suffix := matasano.Base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").Decode()

	plaintext = bytes.Join([][]byte{plaintext, suffix}, []byte{})

	return PersistentAESECBEncrypt(plaintext)
}

func Set2Challenge12Decrypt() []byte {
	e := Encrypter(Set2Challenge12Crypt)
	keysize := e.DiscoverKeysize()
	if !e.IsECB(keysize) {
		log.Fatal("Expected Set2Challenge12Crypt to encrypt as ECB, but it didn't!")
	}

	cipherLen := len(e([]byte("")))
	known := []byte{}
	for len(known) < cipherLen {
		known = append(known, e.DiscoverNextByte(keysize, known))
	}

	return known
}

func discoveryPrefix(keysize int, known []byte) (prefix []byte, candidate []byte) {
	rem := len(known) % keysize
	blockAt := len(known) - rem
	prefix = bytes.Repeat([]byte("A"), keysize-rem-1)
	if blockAt > 0 {
		candidate = known[blockAt-(keysize-rem-1):]
	} else {
		knownpart := known[blockAt:]
		candidate = bytes.Join([][]byte{prefix, knownpart}, []byte(""))
	}
	return

}

func (e Encrypter) DiscoverNextByte(keysize int, known []byte) byte {

	prefix, candidate := discoveryPrefix(keysize, known)

	blockAt := len(known) - (len(known) % keysize)
	base := e(prefix)[blockAt : blockAt+keysize]

	var i int
	candidate = append(candidate, ' ')
	for cipher := []byte{}; i < 256 && !bytes.Equal(cipher, base); i++ {
		candidate[len(candidate)-1] = byte(i)
		cipher = e(candidate)[:keysize]
	}
	if i == 256 {
		return ' '
	} else {
		return byte(i - 1)
	}
}

type Profile map[string][]byte

func (p Profile) AsBytes() []byte {
	parts := make([][]byte, 0)
	for k, v := range p {
		parts = append(parts, []byte(fmt.Sprintf("%s=%s", k, v)))
	}
	return bytes.Join(parts, []byte("&"))
}

func ProfileFor(email []byte) []byte {
	email = bytes.Replace(email, []byte("&"), []byte{}, -1)
	email = bytes.Replace(email, []byte("="), []byte{}, -1)
	return PersistentAESECBEncrypt(Profile{
		"email": email,
		"uid":   []byte("10"),
		"role":  []byte("user"),
	}.AsBytes())
}

func (p Profile) IsAdmin() bool {
	for k, v := range p {
		if k == "role" && bytes.Equal(v, []byte("admin")) {
			return true
		}
	}
	return false
}

func BytesToProfile(src []byte) Profile {
	parts := bytes.Split(src, []byte("&"))
	profile := Profile{}
	for _, p := range parts {
		kv := bytes.SplitN(p, []byte("="), 2)
		profile[string(kv[0])] = kv[1]
	}
	return profile
}

func Set2Challenge13ForceAdminProfile() []byte {
	keysize := Encrypter(ProfileFor).DiscoverKeysize()
	offset := len("email=")
	target := []byte("admin")

	prefix := bytes.Repeat([]byte(" "), keysize-offset)
	suffix := bytes.Repeat([]byte{4}, keysize-len(target))

	profile := ProfileFor(bytes.Join([][]byte{prefix, target, suffix}, []byte{}))

	adminCipher := profile[keysize : keysize*2]

	paddingRequired := keysize - (len("user=&uid=10&role=") % keysize) - 1
	profile = ProfileFor(bytes.Repeat([]byte(" "), paddingRequired))
	copy(profile[len(profile)-keysize:], adminCipher)
	return profile
}

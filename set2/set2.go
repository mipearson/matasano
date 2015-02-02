package set2

import (
	"bytes"

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

func Set2Challenge12Crypt(plaintext []byte) (cipher []byte) {
	suffix := matasano.Base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").Decode()

	plaintext = bytes.Join([][]byte{plaintext, suffix}, []byte{})

	return matasano.EncryptAESECB(matasano.Pkcs7Padding(plaintext, len(PersistentKey())), PersistentKey())
}

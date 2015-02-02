package matasano

import "bytes"

type Encrypter func([]byte) []byte

func RandomECB(plaintext []byte) []byte {
	return EncryptAESECB(Pkcs7Padding(plaintext, 16), RandBytes(16))
}

func RandomCBC(plaintext []byte) []byte {
	return EncryptAESCBC(Pkcs7Padding(plaintext, 16), RandBytes(16), RandBytes(16))
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
	return CipherIsECB(e(plaintext), 16)
}

var CachedPersistentKey []byte

func PersistentKey() []byte {
	if len(CachedPersistentKey) == 0 {
		CachedPersistentKey = RandBytes(16)
	}

	return CachedPersistentKey
}

func Set2Challenge12Crypt(plaintext []byte) (cipher []byte) {
	suffix := Base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").Decode()

	plaintext = bytes.Join([][]byte{plaintext, suffix}, []byte{})

	return EncryptAESECB(Pkcs7Padding(plaintext, len(PersistentKey())), PersistentKey())
}

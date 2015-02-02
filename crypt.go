package matasano

import (
	"bytes"
	"crypto/aes"
)

func DecryptAESECB(cipher []byte, key []byte) []byte {
	aes, err := aes.NewCipher(key)
	CheckErr(err)

	dst := make([]byte, len(cipher))
	for i := 0; i < len(dst); i += aes.BlockSize() {
		aes.Decrypt(dst[i:], cipher[i:])
	}
	return dst
}

func Pkcs7Padding(src []byte, blocksize int) []byte {
	more := blocksize - (len(src) % blocksize)
	dst := make([]byte, len(src)+more)
	copy(dst, src)
	for i := len(src); i < len(dst); i++ {
		dst[i] = 4
	}
	return dst
}

func EncryptAESECB(plaintext []byte, key []byte) []byte {
	aes, err := aes.NewCipher(key)
	CheckErr(err)

	dst := make([]byte, len(plaintext))
	for i := 0; i < len(dst); i += aes.BlockSize() {
		aes.Encrypt(dst[i:], plaintext[i:])
	}
	return dst
}

func DecryptAESCBC(cipher []byte, key []byte, iv []byte) []byte {
	aes, err := aes.NewCipher(key)
	CheckErr(err)

	if len(iv) != aes.BlockSize() {
		panic("aes.BlockSize != len(iv)")
	}

	dst := make([]byte, len(cipher))
	for i := 0; i < len(dst); i += aes.BlockSize() {
		til := i + aes.BlockSize()
		aes.Decrypt(dst[i:], cipher[i:])
		copy(dst[i:til], Xor(dst[i:til], iv))
		iv = cipher[i:]
	}
	return dst
}

func EncryptAESCBC(plaintext []byte, key []byte, iv []byte) []byte {
	aes, err := aes.NewCipher(key)
	CheckErr(err)

	if len(iv) != aes.BlockSize() {
		panic("aes.BlockSize != len(iv)")
	}

	dst := make([]byte, len(plaintext))
	for i := 0; i < len(dst); i += aes.BlockSize() {
		til := i + aes.BlockSize()
		part := Xor(iv, plaintext[i:til])
		aes.Encrypt(dst[i:], part)
		iv = dst[i:til]
	}
	return dst
}

func CipherIsECB(cipher []byte, keysize int) bool {
	for a := 0; a < len(cipher); a += keysize {
		for b := 0; b < len(cipher); b += keysize {
			if a != b && bytes.Equal(cipher[a:a+keysize], cipher[b:b+keysize]) {
				return true
			}
		}
	}
	return false
}

package kms

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

func aesPKCS7Padding(_ciphertext []byte, _blockSize int) []byte {
	padding := _blockSize - len(_ciphertext)%_blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(_ciphertext, padtext...)
}

func aesPKCS7UnPadding(plantText []byte, blockSize int) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}

func aesEncrypt(_plantText []byte, _key []byte) ([]byte, error) {
	if len(_key)%aes.BlockSize != 0 {
		return nil, errors.New("key's length not match 16n")
	}
	block, err := aes.NewCipher(_key)
	if err != nil {
		return nil, err
	}
	iv := _key[:16]
	plantText := aesPKCS7Padding(_plantText, block.BlockSize())
	blockModel := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plantText))
	blockModel.CryptBlocks(ciphertext, plantText)
	return ciphertext, nil
}

func aesDecrypt(_ciphertext []byte, _key []byte) ([]byte, error) {
	if len(_key)%aes.BlockSize != 0 {
		return nil, errors.New("key's length not match 16n")
	}
	if len(_ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	block, err := aes.NewCipher(_key)
	if err != nil {
		return nil, err
	}
	iv := _key[:16]
	blockModel := cipher.NewCBCDecrypter(block, iv)
	plantText := make([]byte, len(_ciphertext))
	blockModel.CryptBlocks(plantText, _ciphertext)
	plantText = aesPKCS7UnPadding(plantText, block.BlockSize())
	return plantText, nil
}

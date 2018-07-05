package kms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func parsePrivateKey(_data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(_data)
	if nil == block {
		return nil, errors.New("private key error")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parsePublicKey(_data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(_data)
	if nil == block {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if nil != err {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return pub, nil
}

//return publickey, privatekey, error
func rsaGenerateKey() ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if nil != err {
		return nil, nil, err
	}
	derStram := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStram,
	}
	privateKeyBytes := pem.EncodeToMemory(block)

	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if nil != err {
		return nil, nil, err
	}
	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPkix,
	}
	publicKeyBytes := pem.EncodeToMemory(block)

	return publicKeyBytes, privateKeyBytes, err
}

//return plantext, error
func rsaDecrypt(_privateKey []byte, _data []byte) ([]byte, error) {
	priv, err := parsePrivateKey(_privateKey)
	if nil != err {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, _data)
}

//return chiphertext, error
func rsaEncrypt(_publicKey []byte, _data []byte) ([]byte, error) {
	pub, err := parsePublicKey(_publicKey)
	if nil != err {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub, _data)
}

func rsaSign(_privateKey []byte, _data []byte) ([]byte, error) {
	hash := crypto.SHA256.New()
	hash.Write(_data)
	hashed := hash.Sum(nil)
	priv, err := parsePrivateKey(_privateKey)
	if nil != err {
		return nil, err
	}
	if nil != err {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
}

func rsaVerify(_publicKey []byte, _data []byte, _sign []byte) error {
	hash := crypto.SHA256.New()
	hash.Write(_data)
	hashed := hash.Sum(nil)
	pub, err := parsePublicKey(_publicKey)
	if nil != err {
		return err
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, _sign)
}

/**
 * @Author: xueyanghan
 * @File: key.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/3 15:54
 */

package utils

import (
	"crypto/ecdsa"
	stdx509 "crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

func PrivateKey2Pem(pkey []byte) []byte {
	pemBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkey,
	}

	return pem.EncodeToMemory(&pemBlock)
}

func KeyPem2PrivateKey(keyPem []byte) (any, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	return ParsePKCS8PrivateKey(block.Bytes)
}

func PublicKey2Pem(pubKey []byte) []byte {
	pemBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKey,
	}

	return pem.EncodeToMemory(&pemBlock)
}

func KeyPem2PublicKey(keyPem []byte) (any, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	return ParsePKIXPublicKey(block.Bytes)
}

func ParsePKCS8PrivateKey(der []byte) (any, error) {
	var (
		key any
	)
	key, err := x509.ParsePKCS8PrivateKey(der, nil)
	if err == nil {
		return key, nil
	}
	key, err = stdx509.ParsePKCS8PrivateKey(der)
	if err == nil {
		return key, nil
	}

	// ed25519
	if len(der) == 64 {
		return der[32:], nil
	}

	return nil, err
}

func ParsePKIXPublicKey(der []byte) (any, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	switch pubKey := pub.(type) {
	case *ecdsa.PublicKey:
		if pubKey.Curve == sm2.P256Sm2() {
			pub = &sm2.PublicKey{
				Curve: sm2.P256Sm2(),
				X:     pubKey.X,
				Y:     pubKey.Y,
			}
		}
	}
	return pub, nil
}

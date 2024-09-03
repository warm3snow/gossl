/**
 * @Author: xueyanghan
 * @File: keygen.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/3 09:31
 */

package asym

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"github.com/warm3snow/gmsm/sm2"
)

type KeyGen struct {
}

func NewKeyGen() *KeyGen {
	return &KeyGen{}
}

func (k *KeyGen) RSAKeyGen(keyBitLen int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keyBitLen)
}

func (k *KeyGen) SM2KeyGen() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

func (k *KeyGen) ECDSAKeyGen(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

/**
 * @Author: xueyanghan
 * @File: ecc-no-hash.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/3 08:52
 */

package asym

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	_const "github.com/warm3snow/gossl/crypto/const"
)

type EccNoHash struct {
}

func NewEccNoHash() *EccNoHash {
	return &EccNoHash{}
}

func (e *EccNoHash) Sign(data []byte, key *ecdsa.PrivateKey, signerOpts crypto.SignerOpts) ([]byte, error) {
	return key.Sign(rand.Reader, data, signerOpts)
}

func (e *EccNoHash) Verify(data, signature []byte, key *ecdsa.PublicKey, signerOpts crypto.SignerOpts) bool {
	return ecdsa.VerifyASN1(key, data, signature)
}

func (e *EccNoHash) Algorithm() _const.Algorithm {
	return _const.Ecdsa
}

func (e *EccNoHash) AlgorithmKind() _const.AlgorithmKind {
	return _const.Asymmetric
}

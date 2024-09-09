/**
 * @Author: xueyanghan
 * @File: ed25519.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/9 14:39
 */

package asym

import (
	"crypto/ed25519"
	_const "github.com/warm3snow/gossl/crypto/const"
)

type Ed25519 struct {
}

func NewEd25519() *Ed25519 {
	return &Ed25519{}
}

func (e *Ed25519) Sign(privateKey, data []byte) (signature []byte, err error) {
	return ed25519.Sign(privateKey, data), nil
}

func (e *Ed25519) Verify(publicKey, data, signature []byte) (valid bool, err error) {
	return ed25519.Verify(publicKey, data, signature), nil
}

func (e *Ed25519) Algorithm() _const.Algorithm {
	return _const.Ed25519
}

func (e *Ed25519) AlgorithKind() _const.AlgorithmKind {
	return _const.Asymmetric
}

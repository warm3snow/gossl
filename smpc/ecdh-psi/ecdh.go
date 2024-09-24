/**
 * @Author: xueyanghan
 * @File: ecdh.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/11 14:00
 */

package ecdh_psi

import (
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"github.com/pkg/errors"
	"github.com/warm3snow/gossl/crypto/asym"
	_const "github.com/warm3snow/gossl/crypto/const"
	"math/big"
)

type EcdhPsi struct {
}

func New() *EcdhPsi {
	return &EcdhPsi{}
}

func (e *EcdhPsi) GenerateKey(curve _const.Curve) (crypto.PrivateKey, error) {
	gen := asym.KeyGen{}
	switch curve {
	case _const.Sm2_curve:
		return gen.SM2KeyGen()
	case _const.ECC_P256:
		return gen.ECDSAKeyGen(elliptic.P256())
	case _const.ECC_P384:
		return gen.ECDSAKeyGen(elliptic.P384())
	case _const.ECC_P521:
		return gen.ECDSAKeyGen(elliptic.P521())
	case _const.Ed25519_curve:
		priv, _, err := gen.Ed25519KeyGen()
		return priv, err
	}
	return nil, errors.New("unsupported curve")
}

func (e *EcdhPsi) Algorithm() _const.Algorithm {
	return "ecdh_psi"
}

func (e *EcdhPsi) AlgorithmKind() _const.AlgorithmKind {
	return "psi"
}

func HashToPoint(data []byte, curve elliptic.Curve) (x, y *big.Int) {
	hash := sha256.Sum256(data)

	z := new(big.Int).SetBytes(hash[:])
	x, y = curve.ScalarBaseMult(z.Bytes())

	return x, y
}

func ScalarMult(curve elliptic.Curve, x, y *big.Int, scalar []byte) (X, Y *big.Int) {
	X, Y = curve.ScalarMult(x, y, scalar)
	return X, Y
}

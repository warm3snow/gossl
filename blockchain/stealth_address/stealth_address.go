/**
 * @Author: xueyanghan
 * @File: stealth_address.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/10/17 10:27
 */

package stealth_address

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/warm3snow/gossl/utils"
	"math/big"
)

type StealthAddress struct {
	curve elliptic.Curve
}

func NewStealthAddress(curve elliptic.Curve) *StealthAddress {
	return &StealthAddress{
		curve: curve,
	}
}

func (sa *StealthAddress) GenRandomPrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(sa.curve, rand.Reader)
}

func (sa *StealthAddress) GenStealthPublicKeyBySender(A, B *ecdsa.PublicKey, r *ecdsa.PrivateKey) *ecdsa.PublicKey {
	// P = H(rA)G + B
	rAx, rAy := sa.curve.ScalarMult(A.X, A.Y, r.D.Bytes())
	HrA := utils.HashPointToPrivateKey(sa.curve, rAx, rAy)
	HrAGx, HrAGy := sa.curve.ScalarBaseMult(HrA.Bytes())
	Px, Py := sa.curve.Add(HrAGx, HrAGy, B.X, B.Y)
	return &ecdsa.PublicKey{
		Curve: sa.curve,
		X:     Px,
		Y:     Py,
	}
}

func (sa *StealthAddress) GenStealthPublicKeyByReceiver(a *ecdsa.PrivateKey, B *ecdsa.PublicKey, R *ecdsa.PublicKey) *ecdsa.PublicKey {
	// P = H(aR)G + B
	aRx, aRy := sa.curve.ScalarMult(R.X, R.Y, a.D.Bytes())
	HaR := utils.HashPointToPrivateKey(sa.curve, aRx, aRy)
	HaRGx, HaRGy := sa.curve.ScalarBaseMult(HaR.Bytes())
	Px, Py := sa.curve.Add(HaRGx, HaRGy, B.X, B.Y)
	return &ecdsa.PublicKey{
		Curve: sa.curve,
		X:     Px,
		Y:     Py,
	}
}

func (sa *StealthAddress) GenStealthPrivateKey(a, b *ecdsa.PrivateKey, R *ecdsa.PublicKey) *ecdsa.PrivateKey {
	// x = H(aR) + b
	aRx, aRy := sa.curve.ScalarMult(R.X, R.Y, a.D.Bytes())
	HaR := utils.HashPointToPrivateKey(sa.curve, aRx, aRy)
	x := new(big.Int).Add(HaR, b.D)
	pubX, pubY := sa.curve.ScalarBaseMult(x.Bytes())

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: sa.curve,
			X:     pubX,
			Y:     pubY,
		},
		D: x,
	}
}

func (sa *StealthAddress) VerifyStealthPublicKey(senderP, receiverP *ecdsa.PublicKey) bool {
	if senderP != nil && receiverP != nil {
		return senderP.X.Cmp(receiverP.X) == 0 && senderP.Y.Cmp(receiverP.Y) == 0
	}
	return false
}

func (sa *StealthAddress) VerifyStealthPrivateKey(senderP *ecdsa.PublicKey, x *ecdsa.PrivateKey) bool {
	if senderP == nil || x == nil {
		return false
	}
	xx, xy := sa.curve.ScalarBaseMult(x.D.Bytes())
	return senderP.X.Cmp(xx) == 0 && senderP.Y.Cmp(xy) == 0
}

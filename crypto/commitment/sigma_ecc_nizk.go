/**
 * @Author: xueyanghan
 * @File: sigma_ecc_nizk.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 16:53
 */

package commitment

import (
	"crypto/elliptic"
	"crypto/rand"
	_const "github.com/warm3snow/gossl/crypto/const"
	"math/big"
)

type SigmaEccNIZKCommitment struct {
	G *ECCPoint

	curve elliptic.Curve

	m, r []byte
	Q    *Point
}

func NewSigmaEccNIZKCommitment(curve elliptic.Curve) *SigmaEccNIZKCommitment {
	return &SigmaEccNIZKCommitment{
		G:     &ECCPoint{curve.Params().Gx, curve.Params().Gy},
		curve: curve,
	}
}

func (sec *SigmaEccNIZKCommitment) Commit(m []byte, r []byte) *Point {
	// Q is the commitment for m
	mInt := new(big.Int).SetBytes(m)
	mGx, mGy := sec.curve.ScalarMult(sec.G.X, sec.G.Y, mInt.Bytes())
	Q := &Point{X: mGx.Bytes(), Y: mGy.Bytes()}

	// save m, not using the r
	sec.m = m
	sec.Q = Q

	return Q
}

func (sec *SigmaEccNIZKCommitment) Open() ([]byte, []byte) {
	//commit for random number r
	var r [32]byte
	_, err := rand.Read(r[:])
	if err != nil {
		panic(err)
	}

	Cx, Cy := sec.curve.ScalarMult(sec.G.X, sec.G.Y, r[:])
	C := &Point{X: Cx.Bytes(), Y: Cy.Bytes()}

	QBytes := PointToBytes(sec.Q, sec.curve)
	CBytes := PointToBytes(C, sec.curve)

	e := new(big.Int).SetBytes(append(QBytes, CBytes...))
	z := new(big.Int).Add(new(big.Int).SetBytes(r[:]), new(big.Int).Mul(e, new(big.Int).SetBytes(sec.m)))

	return e.Bytes(), z.Bytes()
}

func (sec *SigmaEccNIZKCommitment) Verify(Q *Point, e []byte, z []byte) bool {
	eInt := new(big.Int).SetBytes(e)
	zInt := new(big.Int).SetBytes(z)

	// A = zG - eQ
	zGx, zGy := sec.curve.ScalarBaseMult(zInt.Bytes())
	eQx, eQy := sec.curve.ScalarMult(new(big.Int).SetBytes(Q.X), new(big.Int).SetBytes(Q.Y), eInt.Bytes())
	negEQ := PointNegate(&Point{X: eQx.Bytes(), Y: eQy.Bytes()}, sec.curve)
	Ax, Ay := sec.curve.Add(zGx, zGy, new(big.Int).SetBytes(negEQ.X), new(big.Int).SetBytes(negEQ.Y))
	A := &Point{X: Ax.Bytes(), Y: Ay.Bytes()}

	// check e == H(Q, A)
	QBytes := PointToBytes(Q, sec.curve)
	ABytes := PointToBytes(A, sec.curve)
	ePrime := new(big.Int).SetBytes(append(QBytes, ABytes...))

	return eInt.Cmp(ePrime) == 0
}

func (sec *SigmaEccNIZKCommitment) Algorithm() _const.Algorithm {
	return _const.SigmaCommitment
}

func (sec *SigmaEccNIZKCommitment) AlgorithmKind() _const.AlgorithmKind {
	return _const.CommitmentKind
}
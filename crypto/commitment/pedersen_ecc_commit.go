/**
 * @Author: xueyanghan
 * @File: pedersen_ecc_commit.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 16:01
 */

package commitment

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	_const "github.com/warm3snow/gossl/crypto/const"
	"math/big"
)

type PedersenEccCommitment struct {
	G     *ECCPoint
	H     *ECCPoint
	curve elliptic.Curve

	m, r []byte
}

type ECCPoint struct {
	X, Y *big.Int
}

type PedersenEccC struct {
	X, Y *big.Int
}

func NewPedersenEccCommitment(curve elliptic.Curve) *PedersenEccCommitment {
	G := &ECCPoint{X: curve.Params().Gx, Y: curve.Params().Gy}

	// rand H point
	r, err := rand.Prime(rand.Reader, curve.Params().P.BitLen())
	if err != nil {
		panic(err)
	}
	r = new(big.Int).Sub(r, big.NewInt(1))
	Hx, Hy := curve.ScalarBaseMult(r.Bytes())
	H := &ECCPoint{X: Hx, Y: Hy}

	return &PedersenEccCommitment{G: G, H: H, curve: curve}
}

func (pec *PedersenEccCommitment) Commit(m []byte, r []byte) *Point {
	mInt := new(big.Int).SetBytes(m)
	rInt := new(big.Int).SetBytes(r)

	mGx, mGy := pec.curve.ScalarMult(pec.G.X, pec.G.Y, mInt.Bytes())
	rHx, rHy := pec.curve.ScalarMult(pec.H.X, pec.H.Y, rInt.Bytes())

	Cx, Cy := pec.curve.Add(mGx, mGy, rHx, rHy)
	C := &Point{X: Cx.Bytes(), Y: Cy.Bytes()}

	// save m, r
	pec.m, pec.r = m, r

	return C
}

func (pec *PedersenEccCommitment) Open() ([]byte, []byte) {
	return pec.m, pec.r
}

func (pec *PedersenEccCommitment) Verify(C *Point, m, r []byte) bool {
	mInt := new(big.Int).SetBytes(m)
	rInt := new(big.Int).SetBytes(r)

	mGx, mGy := pec.curve.ScalarMult(pec.G.X, pec.G.Y, mInt.Bytes())
	rHx, rHy := pec.curve.ScalarMult(pec.H.X, pec.H.Y, rInt.Bytes())

	Cx, Cy := pec.curve.Add(mGx, mGy, rHx, rHy)

	return bytes.Equal(C.X, Cx.Bytes()) && bytes.Equal(C.Y, Cy.Bytes())
}

func (pec *PedersenEccCommitment) Algorithm() _const.Algorithm {
	return _const.PedersenEccCommitment
}

func (pec *PedersenEccCommitment) AlgorithmKind() _const.AlgorithmKind {
	return _const.CommitmentKind
}

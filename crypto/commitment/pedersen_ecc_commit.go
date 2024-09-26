/**
 * @Author: xueyanghan
 * @File: pedersen_ecc_commit.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 16:01
 */

package commitment

import (
	"crypto/elliptic"
	"crypto/rand"
	_const "github.com/warm3snow/gossl/crypto/const"
	"math/big"
)

type PedersenEccCommitment struct {
	G     *Point
	H     *Point
	curve elliptic.Curve

	m, r []byte
}

func NewPedersenEccCommitment(curve elliptic.Curve) *PedersenEccCommitment {
	G := &Point{X: curve.Params().Gx, Y: curve.Params().Gy}

	// rand H point
	var r [32]byte
	_, err := rand.Read(r[:])
	if err != nil {
		panic(err)
	}
	Hx, Hy := curve.ScalarBaseMult(r[:])
	H := &Point{X: Hx, Y: Hy}

	return &PedersenEccCommitment{G: G, H: H, curve: curve}
}

func (pec *PedersenEccCommitment) GetCommonParams() (G, H string) {
	return pec.G.String(), pec.H.String()
}

func (pec *PedersenEccCommitment) SetCommonParams(G, H string) {
	pec.G.FromString(G)
	pec.H.FromString(H)
}

func (pec *PedersenEccCommitment) Commit(m []byte, r []byte) *Point {
	mInt := new(big.Int).SetBytes(m)
	rInt := new(big.Int).SetBytes(r)

	mGx, mGy := pec.curve.ScalarMult(pec.G.X, pec.G.Y, mInt.Bytes())
	rHx, rHy := pec.curve.ScalarMult(pec.H.X, pec.H.Y, rInt.Bytes())

	Cx, Cy := pec.curve.Add(mGx, mGy, rHx, rHy)
	C := &Point{X: Cx, Y: Cy}

	// save m, r
	pec.m, pec.r = m, r

	return C
}

func (pec *PedersenEccCommitment) Open() ([]byte, []byte) {
	return pec.m, pec.r
}

func (pec *PedersenEccCommitment) Verify(CC *Point, m, r []byte) bool {
	mInt := new(big.Int).SetBytes(m)
	rInt := new(big.Int).SetBytes(r)

	mGx, mGy := pec.curve.ScalarMult(pec.G.X, pec.G.Y, mInt.Bytes())
	rHx, rHy := pec.curve.ScalarMult(pec.H.X, pec.H.Y, rInt.Bytes())

	Cx, Cy := pec.curve.Add(mGx, mGy, rHx, rHy)

	return Cx.Cmp(CC.X) == 0 && Cy.Cmp(CC.Y) == 0
}

func (pec *PedersenEccCommitment) Algorithm() _const.Algorithm {
	return _const.PedersenEccCommitment
}

func (pec *PedersenEccCommitment) AlgorithmKind() _const.AlgorithmKind {
	return _const.CommitmentKind
}

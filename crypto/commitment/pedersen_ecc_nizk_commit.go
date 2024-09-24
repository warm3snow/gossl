/**
 * @Author: xueyanghan
 * @File: pedersen_ecc_nizk_commit.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 16:28
 */

package commitment

import (
	"crypto/elliptic"
	"crypto/rand"
	_const "github.com/warm3snow/gossl/crypto/const"
	"math/big"
)

type PedersenEccNIZKCommitment struct {
	G     *ECCPoint
	H     *ECCPoint
	curve elliptic.Curve

	m, r []byte
}

func NewPedersenEccNIZKCommitment(curve elliptic.Curve) *PedersenEccNIZKCommitment {
	G := &ECCPoint{X: curve.Params().Gx, Y: curve.Params().Gy}

	// rand H point
	r, err := rand.Prime(rand.Reader, curve.Params().P.BitLen())
	if err != nil {
		panic(err)
	}
	r = new(big.Int).Sub(r, big.NewInt(1))
	Hx, Hy := curve.ScalarBaseMult(r.Bytes())
	H := &ECCPoint{X: Hx, Y: Hy}

	return &PedersenEccNIZKCommitment{G: G, H: H, curve: curve}
}

func (pec *PedersenEccNIZKCommitment) Commit(m []byte, r []byte) *Point {
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

func (pec *PedersenEccNIZKCommitment) Open() (*Point, []byte, []byte) {
	// Opening P, x, y

	// x, y
	var xBytes, yBytes [32]byte
	_, err := rand.Read(xBytes[:])
	if err != nil {
		panic(err)
	}
	_, err = rand.Read(yBytes[:])
	if err != nil {
		panic(err)
	}
	x, y := new(big.Int).SetBytes(xBytes[:]), new(big.Int).SetBytes(yBytes[:])

	// P = xG + yH
	xGx, xGy := pec.curve.ScalarMult(pec.G.X, pec.G.Y, x.Bytes())
	yHx, yHy := pec.curve.ScalarMult(pec.H.X, pec.H.Y, y.Bytes())
	Px, Py := pec.curve.Add(xGx, xGy, yHx, yHy)
	P := &Point{X: Px.Bytes(), Y: Py.Bytes()}

	// H(P)
	hBytes := PointToBytes(P, pec.curve)
	h := new(big.Int).SetBytes(hBytes)

	// x', y'
	xx := new(big.Int).Add(x, new(big.Int).Mul(h, new(big.Int).SetBytes(pec.m)))
	yy := new(big.Int).Add(y, new(big.Int).Mul(h, new(big.Int).SetBytes(pec.r)))

	return P, xx.Bytes(), yy.Bytes()
}

// Verify the commitment
// note here, x, y actually are x', y'
func (pec *PedersenEccNIZKCommitment) Verify(C *Point, P *Point, x, y []byte) bool {
	// P + h * C
	h := new(big.Int).SetBytes(PointToBytes(P, pec.curve))
	hCx, hCy := pec.curve.ScalarMult(new(big.Int).SetBytes(C.X), new(big.Int).SetBytes(C.Y), h.Bytes())
	Cx, Cy := pec.curve.Add(new(big.Int).SetBytes(P.X), new(big.Int).SetBytes(P.Y), hCx, hCy)

	// xG + yH
	xGx, xGy := pec.curve.ScalarMult(pec.G.X, pec.G.Y, new(big.Int).SetBytes(x).Bytes())
	yHx, yHy := pec.curve.ScalarMult(pec.H.X, pec.H.Y, new(big.Int).SetBytes(y).Bytes())
	Px, Py := pec.curve.Add(xGx, xGy, yHx, yHy)

	return Px.Cmp(Cx) == 0 && Py.Cmp(Cy) == 0
}

func (pec *PedersenEccNIZKCommitment) Algorithm() _const.Algorithm {
	return _const.PedersenEccNIZKCommitment
}

func (pec *PedersenEccNIZKCommitment) AlgorithmKind() _const.AlgorithmKind {
	return _const.CommitmentKind
}

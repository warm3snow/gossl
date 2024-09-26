/**
 * @Author: xueyanghan
 * @File: elgamal_commit.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 14:15
 */

package commitment

import (
	"crypto/rand"
	_const "github.com/warm3snow/gossl/crypto/const"
	"math/big"
)

type ElGamalCommitment struct {
	g, h *big.Int
	p    *big.Int

	m, r []byte
}

func NewElGamalCommitment(bitSize int) *ElGamalCommitment {
	p, err := rand.Prime(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}
	g := big.NewInt(2)
	h := big.NewInt(3)

	return &ElGamalCommitment{g: g, p: p, h: h}
}

func (ec *ElGamalCommitment) GetCommonParams() (g, h, p string) {
	return ec.g.String(), ec.h.String(), ec.p.String()
}

func (ec *ElGamalCommitment) SetCommonParams(g, h, p string) {
	ec.g.SetString(g, 10)
	ec.h.SetString(h, 10)
	ec.p.SetString(p, 10)
}

func (ec *ElGamalCommitment) Commit(m []byte, r []byte) *Point {
	mInt := new(big.Int).SetBytes(m)
	rInt := new(big.Int).SetBytes(r)

	G := new(big.Int).Exp(ec.g, rInt, ec.p)
	mH := new(big.Int).Mul(mInt, new(big.Int).Exp(ec.h, rInt, ec.p))

	ec.m, ec.r = m, r

	return &Point{G, mH}
}

func (ec *ElGamalCommitment) Open() ([]byte, []byte) {
	return ec.m, ec.r
}

func (ec *ElGamalCommitment) Verify(CC *Point, m, r []byte) bool {
	mInt := new(big.Int).SetBytes(m)
	rInt := new(big.Int).SetBytes(r)

	G := new(big.Int).Exp(ec.g, rInt, ec.p)
	mH := new(big.Int).Mul(mInt, new(big.Int).Exp(ec.h, rInt, ec.p))

	return G.Cmp(CC.X) == 0 && mH.Cmp(CC.Y) == 0
}

func (ec *ElGamalCommitment) Algorithm() _const.Algorithm {
	return _const.ElGamalCommitment
}

func (ec *ElGamalCommitment) AlgorithmKind() _const.AlgorithmKind {
	return _const.CommitmentKind
}

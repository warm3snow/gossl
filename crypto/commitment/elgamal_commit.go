/**
 * @Author: xueyanghan
 * @File: elgamal_commit.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 14:15
 */

package commitment

import (
	"bytes"
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

func (ec *ElGamalCommitment) Commit(m []byte, r []byte) *Point {
	mInt := new(big.Int).SetBytes(m)
	rInt := new(big.Int).SetBytes(r)

	G := new(big.Int).Exp(ec.g, rInt, ec.p)
	mH := new(big.Int).Mul(mInt, new(big.Int).Exp(ec.h, rInt, ec.p))

	ec.m, ec.r = m, r

	return &Point{G.Bytes(), mH.Bytes()}
}

func (ec *ElGamalCommitment) Open() ([]byte, []byte) {
	return ec.m, ec.r
}

func (ec *ElGamalCommitment) Verify(C *Point, m, r []byte) bool {
	mInt := new(big.Int).SetBytes(m)
	rInt := new(big.Int).SetBytes(r)

	G := new(big.Int).Exp(ec.g, rInt, ec.p)
	mH := new(big.Int).Mul(mInt, new(big.Int).Exp(ec.h, rInt, ec.p))

	return bytes.Equal(G.Bytes(), C.X) && bytes.Equal(mH.Bytes(), C.Y)
}

func (ec *ElGamalCommitment) Algorithm() _const.Algorithm {
	return _const.ElGamalCommitment
}

func (ec *ElGamalCommitment) AlgorithmKind() _const.AlgorithmKind {
	return _const.CommitmentKind
}

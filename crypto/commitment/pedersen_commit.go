/**
 * @Author: xueyanghan
 * @File: pedersen_commit.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 15:56
 */

package commitment

import (
	"bytes"
	"crypto/rand"
	_const "github.com/warm3snow/gossl/crypto/const"
	"math/big"
)

type PedersenCommitment struct {
	g, h, p *big.Int

	m, r []byte
}

func NewPedersenCommitment(bitSize int) *PedersenCommitment {
	p, err := rand.Prime(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}
	// g, h are generators of group Zp
	g := big.NewInt(2)
	h := big.NewInt(3)

	return &PedersenCommitment{g: g, h: h, p: p}
}

func (pc *PedersenCommitment) Commit(m []byte, r []byte) []byte {
	mInt := new(big.Int).SetBytes(m)
	rInt := new(big.Int).SetBytes(r)

	G := new(big.Int).Exp(pc.g, mInt, pc.p)
	H := new(big.Int).Exp(pc.h, rInt, pc.p)

	GH := new(big.Int).Mul(G, H)

	pc.m, pc.r = m, r

	return GH.Bytes()
}

func (pc *PedersenCommitment) Open() ([]byte, []byte) {
	return pc.m, pc.r
}

func (pc *PedersenCommitment) Verify(C, m, r []byte) bool {
	return bytes.Equal(pc.Commit(m, r), C)
}

func (pc *PedersenCommitment) Algorithm() _const.Algorithm {
	return _const.PedersenCommitment
}

func (pc *PedersenCommitment) AlgorithmKind() _const.AlgorithmKind {
	return _const.CommitmentKind
}

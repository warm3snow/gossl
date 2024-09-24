/**
 * @Author: xueyanghan
 * @File: hash_commit.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 11:51
 */

package commitment

import (
	"bytes"
	"crypto/sha256"
	_const "github.com/warm3snow/gossl/crypto/const"
	"hash"
)

type HashCommitment struct {
	h hash.Hash

	m, r []byte
}

func NewHashCommitment(h hash.Hash) *HashCommitment {
	return &HashCommitment{h: h}
}

func (hc *HashCommitment) Commit(m []byte, r []byte) []byte {
	h := sha256.New()
	h.Write(m)

	hc.m, hc.r = m, r

	return h.Sum(nil)
}

func (hc *HashCommitment) Open() ([]byte, []byte) {
	return hc.m, hc.r
}

func (hc *HashCommitment) Verify(C, m, r []byte) bool {
	return bytes.Equal(hc.Commit(m, r), C)
}

func (hc *HashCommitment) Algorithm() _const.Algorithm {
	return _const.HashCommitment
}

func (hc *HashCommitment) AlgorithmKind() _const.AlgorithmKind {
	return _const.CommitmentKind
}

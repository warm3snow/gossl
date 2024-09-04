/**
 * @Author: xueyanghan
 * @File: sha256.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 20:35
 */

package dgst

import (
	"crypto/sha256"
	_const "github.com/warm3snow/gossl/crypto/const"
)

type Sha256 struct {
}

func (s *Sha256) Sum(data []byte) []byte {
	d := sha256.Sum256(data)
	return d[:]
}

func (s *Sha256) Algorithm() _const.Algorithm {
	return _const.Sha256
}

func (s *Sha256) AlgorithmKind() _const.AlgorithmKind {
	return _const.Digest
}

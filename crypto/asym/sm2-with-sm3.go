/**
 * @Author: xueyanghan
 * @File: sm2-with-sm3.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/3 08:43
 */

package asym

import (
	"crypto/rand"
	"github.com/tjfoc/gmsm/sm2"
	_const "github.com/warm3snow/gossl/crypto/const"
)

type Sm2WithSm3 struct {
}

func NewSm2WithSm3() *Sm2WithSm3 {
	return &Sm2WithSm3{}
}

func (s *Sm2WithSm3) Sign(data []byte, key *sm2.PrivateKey) ([]byte, error) {
	return key.Sign(rand.Reader, data, nil)
}

func (s *Sm2WithSm3) Verify(data, signature []byte, key *sm2.PublicKey) bool {
	return key.Verify(data, signature)
}

func (s *Sm2WithSm3) Algorithm() _const.Algorithm {
	return _const.Sm2
}

func (s *Sm2WithSm3) AlgorithmKind() _const.AlgorithmKind {
	return _const.Asymmetric
}

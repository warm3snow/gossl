/**
 * @Author: xueyanghan
 * @File: sm4-cbc.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 17:30
 */

package sym

import (
	"github.com/tjfoc/gmsm/sm4"
	_const "github.com/warm3snow/gossl/crypto/const"
)

type Sm4Cbc struct {
}

func NewSm4Cbc() *Sm4Cbc {
	return &Sm4Cbc{}
}

func (s *Sm4Cbc) Encrypt(key, plainText []byte) ([]byte, error) {
	return sm4.Sm4Cbc(key, plainText, true)
}

func (s *Sm4Cbc) Decrypt(key, cipherText []byte) ([]byte, error) {
	return sm4.Sm4Cbc(key, cipherText, false)
}

func (s *Sm4Cbc) Algorithm() _const.Algorithm {
	return _const.Sm4Cbc
}

func (s *Sm4Cbc) AlgorithmKind() _const.AlgorithmKind {
	return _const.Symmetric
}

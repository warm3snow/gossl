/**
 * @Author: xueyanghan
 * @File: sm4-cbc.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 17:30
 */

package sym

import "github.com/warm3snow/gmsm/sm4"

type Sm4Cbc struct {
}

func NewSm4Cbc() *Sm4Cbc {
	return &Sm4Cbc{}
}

func (s *Sm4Cbc) Encrypt(key, iv, plainText []byte) ([]byte, error) {
	return sm4.Sm4Cbc([]byte(key), plainText, true)
}

func (s *Sm4Cbc) Decrypt(key, iv, cipherText []byte) ([]byte, error) {
	return sm4.Sm4Cbc([]byte(key), cipherText, false)
}

func (s *Sm4Cbc) GetAlgorithm() string {
	return "sm4-cbc"
}

func (s *Sm4Cbc) GetAlgorithmKind() string {
	return "symmetric"
}

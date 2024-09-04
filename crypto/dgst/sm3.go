/**
 * @Author: xueyanghan
 * @File: sm3.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 20:35
 */

package dgst

import (
	"github.com/tjfoc/gmsm/sm3"
	_const "github.com/warm3snow/gossl/crypto/const"
)

type Sm3 struct {
}

func (s Sm3) Sum(data []byte) []byte {
	return sm3.Sm3Sum(data)
}

func (s Sm3) Algorithm() _const.Algorithm {
	return _const.Sm3
}

func (s Sm3) AlgorithmKind() _const.AlgorithmKind {
	return _const.Digest
}

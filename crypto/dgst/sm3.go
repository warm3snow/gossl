/**
 * @Author: xueyanghan
 * @File: sm3.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 20:35
 */

package dgst

import "github.com/tjfoc/gmsm/sm3"

type Sm3 struct {
}

func (s Sm3) Sum(data []byte) []byte {
	return sm3.Sm3Sum(data)
}

func (s Sm3) Algorithm() string {
	return "sm3"
}

func (s Sm3) AlgorithmKind() string {
	return "digest"
}

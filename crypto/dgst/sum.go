/**
 * @Author: xueyanghan
 * @File: sum.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/3 12:12
 */

package dgst

import (
	"crypto/sha256"
	"github.com/tjfoc/gmsm/sm3"
	"golang.org/x/crypto/sha3"
)

func Sum(algo string, data []byte) []byte {
	switch algo {
	case "sha256":
		res := sha256.Sum256(data)
		return res[:]
	case "sha384":
		res := sha3.Sum384(data)
		return res[:]
	case "sha512":
		res := sha3.Sum512(data)
		return res[:]
	case "sm3":
		return sm3.Sm3Sum(data)
	}
	return nil
}

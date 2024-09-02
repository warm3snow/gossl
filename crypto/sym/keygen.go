/**
 * @Author: xueyanghan
 * @File: keygen.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 19:46
 */

package sym

import (
	"crypto/rand"
	"github.com/pkg/errors"
)

type KeyGen struct {
}

func NewKeyGen() *KeyGen {
	return &KeyGen{}
}

func (k *KeyGen) GenKey(len int) ([]byte, error) {
	key := make([]byte, len)

	// TODO: rand could fill less bytes then len
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.Wrap(err, "error getting random bytes")
	}

	return key, nil
}

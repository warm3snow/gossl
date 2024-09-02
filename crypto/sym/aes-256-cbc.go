/**
 * @Author: xueyanghan
 * @File: aes-256-cbc.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 17:28
 */

package sym

type Aes256Cbc struct {
}

func NewAes256Cbc() *Aes256Cbc {
	return &Aes256Cbc{}
}

func (a *Aes256Cbc) Encrypt(key, iv, plainText []byte) ([]byte, error) {
	return nil, nil
}

func (a *Aes256Cbc) Decrypt(key, iv, cipherText []byte) ([]byte, error) {
	return nil, nil
}

func (a *Aes256Cbc) GetAlgorithm() string {
	return "aes-256-cbc"
}

func (a *Aes256Cbc) GetAlgorithmKind() string {
	return "symmetric"
}

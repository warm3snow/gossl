/**
 * @Author: xueyanghan
 * @File: aes-256-cbc.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 17:28
 */

package sym

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/pkg/errors"
	"github.com/warm3snow/gossl/utils"
	"io"
)

type Aes256Cbc struct {
}

func NewAes256Cbc() *Aes256Cbc {
	return &Aes256Cbc{}
}

func (a *Aes256Cbc) Encrypt(key, plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := utils.Pad(plainText, block.BlockSize())
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func (a *Aes256Cbc) Decrypt(key, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	return utils.Unpad(cipherText)
}

func (a *Aes256Cbc) GetAlgorithm() string {
	return "aes-256-cbc"
}

func (a *Aes256Cbc) GetAlgorithmKind() string {
	return "symmetric"
}

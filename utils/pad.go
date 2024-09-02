/**
 * @Author: xueyanghan
 * @File: pad.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 20:04
 */

package utils

import (
	"bytes"
	"github.com/pkg/errors"
)

// Pad adds padding to the plaintext to make its length a multiple of the block size
func Pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// Unpad removes padding from the plaintext
func Unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding")
	}
	return src[:(length - unpadding)], nil
}

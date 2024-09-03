/**
 * @Author: xueyanghan
 * @File: encode.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 19:35
 */

package utils

import (
	"encoding/hex"
)

func Hex2Bytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

func Bytes2Hex(b []byte) string {
	return hex.EncodeToString(b)
}

func KeyFile2PrivateKey(keyFile string) (any, error) {
	keyPem, err := ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return KeyPem2PrivateKey(keyPem)
}

func KeyFile2PublicKey(keyFile string) (any, error) {
	keyPem, err := ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return KeyPem2PublicKey(keyPem)
}

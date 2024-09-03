/**
 * @Author: xueyanghan
 * @File: encode_decode.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 19:35
 */

package utils

import (
	"encoding/hex"
	"encoding/pem"
	"github.com/pkg/errors"
)

func Hex2Bytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

func Bytes2Hex(b []byte) string {
	return hex.EncodeToString(b)
}

func PKey2Pem(pkey []byte) []byte {
	pemBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkey,
	}

	return pem.EncodeToMemory(&pemBlock)
}

func Pem2PKey(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	return block.Bytes, nil
}

/**
 * @Author: xueyanghan
 * @File: encode_decode.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 19:35
 */

package utils

import "encoding/hex"

func Hex2Bytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

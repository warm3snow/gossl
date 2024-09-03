/**
 * @Author: xueyanghan
 * @File: file.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 19:23
 */

package utils

import (
	"os"
)

func ReadFile(fileName string) ([]byte, error) {
	return os.ReadFile(fileName)
}

func WriteFile(fileName string, data []byte) error {
	return os.WriteFile(fileName, data, 0666)
}

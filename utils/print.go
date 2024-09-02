/**
 * @Author: xueyanghan
 * @File: print.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 19:53
 */

package utils

import "io"

// print s to
func Print(s []byte, writer io.WriteCloser) error {
	_, err := writer.Write(s)
	return err
}

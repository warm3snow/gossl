/**
 * @Author: xueyanghan
 * @File: asym_test.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/3 16:18
 */

package asym

import (
	"crypto/rand"
	"github.com/tjfoc/gmsm/sm2"
	"testing"
)

func TestSm2WithSm3(t *testing.T) {
	sm2WithSm3 := NewSm2WithSm3()
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey
	data := []byte("data")
	signature, err := sm2WithSm3.Sign(data, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if !sm2WithSm3.Verify(data, signature, publicKey) {
		t.Fatal("failed to verify")
	}
}

/**
 * @Author: xueyanghan
 * @File: helper_test.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/8 12:25
 */

package gmtls

import (
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"testing"
)

func TestSM2SignVerify(t *testing.T) {
	priv, err := sm2.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := []byte("hello")
	uid := []byte("1234567812345678")
	sig, err := SM2Sign(priv, hash, uid)
	if err != nil {
		t.Fatal(err)
	}
	if !SM2Verify(&priv.PublicKey, hash, sig, uid) {
		t.Fatal("SM2Verify failed")
	}
}

func TestTjfocSM2SignVerify(t *testing.T) {
	priv, err := sm2.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := []byte("hello")

	{
		sig, _ := priv.Sign(nil, hash, nil)
		if !priv.PublicKey.Verify(hash, sig) {
			t.Fatal("SM2Verify2 failed")
		} else {
			fmt.Println("SM2Verify2 success")
		}
	}

	uid := []byte("1234567812345678")
	r, s, err := sm2.Sm2Sign(priv, hash, uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("r: %x\n", r)
	fmt.Printf("s: %x\n", s)
	if !sm2.Verify(&priv.PublicKey, hash, r, s) {
		t.Fatal("SM2Verify failed")
	}
}

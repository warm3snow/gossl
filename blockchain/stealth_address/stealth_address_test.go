/**
 * @Author: xueyanghan
 * @File: stealth_address_test.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/10/17 11:42
 */

package stealth_address

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestNewStealthAddress(t *testing.T) {
	curve := elliptic.P256()
	steathAddress := NewStealthAddress(curve)

	a, _ := steathAddress.GenRandomPrivateKey()
	b, _ := steathAddress.GenRandomPrivateKey()
	r, _ := steathAddress.GenRandomPrivateKey()

	// P = H(rA)G + B
	P1 := steathAddress.GenStealthPublicKeyBySender(&a.PublicKey, &b.PublicKey, r)
	fmt.Println("r = ", r.D)
	rPub := elliptic.MarshalCompressed(curve, r.X, r.Y)
	fmt.Println("R = ", hex.EncodeToString(rPub))

	P1Pub := elliptic.MarshalCompressed(curve, P1.X, P1.Y)
	fmt.Printf("P = H(rA)G + B = %s\n", hex.EncodeToString(P1Pub))

	// P' = H(aR)G + B
	P2 := steathAddress.GenStealthPublicKeyByReceiver(a, &b.PublicKey, &r.PublicKey)
	P2Pub := elliptic.MarshalCompressed(curve, P2.X, P2.Y)
	fmt.Printf("P' = H(aR)G + B = %s\n", hex.EncodeToString(P2Pub))

	// P =? P'
	verifyP := steathAddress.VerifyStealthPublicKey(P1, P2)
	if !verifyP {
		t.Error("verifyP failed: P != P'")
	} else {
		fmt.Println("verifyP success: P = P'")
	}

	fmt.Println("=====================")
	// x = H(aR) + b
	x := steathAddress.GenStealthPrivateKey(a, b, &r.PublicKey)
	fmt.Printf("x = H(aR) + b = %v\n", x.D)
	fmt.Printf("P = H(rA)G + B = %s\n", hex.EncodeToString(P1Pub))
	// P = xG
	verifyX := steathAddress.VerifyStealthPrivateKey(P1, x)
	if !verifyX {
		t.Error("verifyX failed: P != xG")
	} else {
		fmt.Println("verifyX success: P = xG")
	}
}

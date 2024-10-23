/**
 * @Author: xueyanghan
 * @File: ring_signature_test.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/10/23 22:27
 */

package ring_signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRingSignature(t *testing.T) {
	r := NewRingSignature()
	curve := elliptic.P256()

	// Pick random ring
	ring := make([]*ecdsa.PublicKey, 10)
	for i := 0; i < 10; i++ {
		pri, _ := ecdsa.GenerateKey(curve, rand.Reader)
		ring[i] = &pri.PublicKey
	}

	// KeyGen
	xs, I := r.KeyGen(curve)

	// put the public key of the signer in the ring
	ring[4] = &xs.PublicKey

	// Sign
	msg := []byte("hello world")
	sig, err := r.Sign(xs, msg, ring, I)
	assert.NoError(t, err)

	// Verify
	pass := r.Verify(msg, ring, sig)
	assert.True(t, pass)
}

/**
 * @Author: xueyanghan
 * @File: commitment_test.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 16:59
 */

package commitment

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
	"testing"
)

func TestNewHashCommitment(t *testing.T) {
	hc := NewHashCommitment(sha3.New256())
	assert.NotNil(t, hc)

	CC := hc.Commit([]byte("hello"), nil)
	m, _ := hc.Open()

	assert.True(t, hc.Verify(CC, m, nil))
}

func TestNewElGamalCommitment(t *testing.T) {
	ec := NewElGamalCommitment(1024)
	assert.NotNil(t, ec)

	CC := ec.Commit([]byte("hello"), []byte("world"))
	m, r := ec.Open()

	assert.True(t, ec.Verify(CC, m, r))
}

func TestNewPedersenCommitment(t *testing.T) {
	pc := NewPedersenCommitment(1024)
	assert.NotNil(t, pc)

	var rBytes [32]byte
	_, err := rand.Read(rBytes[:])
	assert.NoError(t, err)

	CC := pc.Commit([]byte("hello"), rBytes[:])
	m, r := pc.Open()

	assert.True(t, pc.Verify(CC, m, r))
}

func TestNewPedersenEccCommitment(t *testing.T) {
	pec := NewPedersenEccCommitment(elliptic.P256())
	assert.NotNil(t, pec)

	CC := pec.Commit([]byte("hello"), []byte("world"))
	m, r := pec.Open()

	assert.True(t, pec.Verify(CC, m, r))
}

func TestNewPedersenEccNIZKCommitment(t *testing.T) {
	pec := NewPedersenEccNIZKCommitment(elliptic.P256())
	assert.NotNil(t, pec)

	CC := pec.Commit([]byte("hello"), []byte("world"))
	P, x, y := pec.Open()

	assert.True(t, pec.Verify(CC, P, x, y))
}

func TestNewSigmaEccNIZKCommitment(t *testing.T) {
	sec := NewSigmaEccNIZKCommitment(elliptic.P256())
	assert.NotNil(t, sec)

	var r [32]byte
	_, err := rand.Read(r[:])
	assert.NoError(t, err)

	Q := sec.Commit([]byte("hello"), r[:])
	x, y := sec.Open()

	var (
		cc Point
	)
	cc.FromString(Q.String())

	assert.True(t, sec.Verify(&cc, x, y))
}

/**
 * @Author: xueyanghan
 * @File: scryptimpl_test.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2023/9/19 15:26
 */

package scryptimpl

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	kdfimpl *ScryptImpl
)

func TestMain(m *testing.M) {
	kdfimpl = New(-1, -1, -1, -1)
	m.Run()
}

func TestScryptImpl(t *testing.T) {
	_, err := kdfimpl.DeriveKeyByPassword("123456")
	assert.NoError(t, err)

	dkStr1 := kdfimpl.GetDeriveKeyStr()
	dkStr2 := kdfimpl.GetDeriveKeyStr()
	assert.Equal(t, dkStr1, dkStr2)
	t.Log("DeriveKeyStr:", dkStr1)

	isOk, err := kdfimpl.VerifyDeriveKeyStr(dkStr1, []byte("123456"))
	assert.NoError(t, err)
	assert.True(t, isOk)
}

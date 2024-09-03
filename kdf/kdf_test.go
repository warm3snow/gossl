/**
 * @Author: xueyanghan
 * @File: password.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2023/9/18 14:44
 */

package kdf

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKDF(t *testing.T) {
	testCases := []struct {
		kdfName string
		keyLen  int
		err     error
	}{
		{
			kdfName: BCRYPT,
			keyLen:  32,
			err:     nil,
		},
		{
			kdfName: PBKDF2,
			keyLen:  32,
			err:     nil,
		},
		{
			kdfName: SCRYPT,
			keyLen:  32,
			err:     nil,
		},
		{
			kdfName: ARGON2,
			keyLen:  32,
			err:     nil,
		},
		{
			kdfName: "fakeKDF",
			keyLen:  32,
			err:     errors.Errorf("kdfName %s not supported", "fakeKDF"),
		},
	}
	password, err := GenerateRandomPassword(8, 3)
	assert.NoError(t, err)
	fmt.Printf("明文密码: %s\n", password)

	for _, testCase := range testCases {
		kdf, err := InitKdf(testCase.kdfName, testCase.keyLen)
		if testCase.err != nil {
			assert.EqualError(t, err, testCase.err.Error())
			continue
		}
		assert.NoError(t, err)

		deriveKey, err := kdf.DeriveKeyByPassword(password)
		assert.NoError(t, err)
		assert.NotNil(t, deriveKey)

		kdfKeyStr := kdf.GetDeriveKeyStr()
		assert.NotEmpty(t, kdfKeyStr)
		fmt.Printf("密文密码: %s\n", kdfKeyStr)

		isOk, err := kdf.VerifyDeriveKeyStr(kdfKeyStr, []byte(password))
		assert.NoError(t, err)
		assert.True(t, isOk)
		fmt.Printf("验证密文密码: %v\n", isOk)
	}
}

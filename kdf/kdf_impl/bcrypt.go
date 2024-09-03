/**
 * @Author: xueyanghan
 * @File: bcrypt.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2023/9/19 15:54
 */

package kdf_impl

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

type BcryptImpl struct {
	cost      int
	deriveKey []byte
}

func NewBcryptImpl(cost int) *BcryptImpl {
	return &BcryptImpl{cost: cost}
}

func (b *BcryptImpl) DeriveKeyByPassword(password string) (deriveKey []byte, err error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), b.cost)
	if err != nil {
		return nil, errors.Wrap(err, "bcrypt.GenerateFromPassword error")
	}
	b.deriveKey = hashedPassword
	return hashedPassword, nil
}

func (b *BcryptImpl) VerifyDeriveKeyStr(kdfKeyStr string, password []byte) (isOk bool, err error) {
	kdfKeyStr = strings.TrimPrefix(kdfKeyStr, "$")
	if !strings.HasPrefix(kdfKeyStr, b.Algorithm()) {
		return false, errors.New("kdfKeyStr format error, not bcrypt")
	}
	kdfKeyStr = strings.TrimPrefix(kdfKeyStr, b.Algorithm())
	err = bcrypt.CompareHashAndPassword([]byte(kdfKeyStr), password)
	if err != nil {
		return false, errors.Wrap(err, "bcrypt.CompareHashAndPassword error")
	}
	return true, nil
}

func (b *BcryptImpl) GetDeriveKeyStr() string {
	// key format: $bcrypt$bcrpytFormatKey
	return "$" + b.Algorithm() + string(b.deriveKey)
}

func (b *BcryptImpl) Algorithm() string {
	return "bcrypt"
}

func (b *BcryptImpl) AlgorithmKind() string {
	return "kdf"
}

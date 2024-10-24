/**
 * @Author: xueyanghan
 * @File: pbkdf2.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2023/9/19 16:02
 */

package kdf_impl

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	_const "github.com/warm3snow/gossl/crypto/const"
	"golang.org/x/crypto/pbkdf2"
	"strconv"
	"strings"
)

var (
	defaultHashFunc = sha256.New
)

type Pbkdf2Impl struct {
	iters   int
	keyLen  int
	saltLen int

	salt      []byte
	deriveKey []byte
}

func NewPbkdf2Impl(iters, keyLen, saltLen int) *Pbkdf2Impl {
	impl := &Pbkdf2Impl{
		iters:   iters,
		keyLen:  keyLen,
		saltLen: saltLen,
	}
	return impl
}

func (p *Pbkdf2Impl) DeriveKeyByPassword(password string) (deriveKey []byte, err error) {
	salt := make([]byte, p.saltLen)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, errors.Wrap(err, "rand.Read error")
	}
	p.salt = salt
	p.deriveKey = pbkdf2.Key([]byte(password), salt, p.iters, p.keyLen, defaultHashFunc)

	return p.deriveKey, nil
}

func (p *Pbkdf2Impl) VerifyDeriveKeyStr(kdfKeyStr string, password []byte) (isOk bool, err error) {
	kdfKeyStr = strings.TrimLeft(kdfKeyStr, "$")
	kdfKeyStrs := strings.Split(kdfKeyStr, "$")
	if len(kdfKeyStrs) != 4 {
		return false, errors.New("kdfKeyStr format error, not 4 parts")
	}
	if kdfKeyStrs[0] != "pbkdf2" {
		return false, errors.New("kdfKeyStr format error, not pbkdf2")
	}
	salt, err := base64.StdEncoding.DecodeString(kdfKeyStrs[1])
	if err != nil {
		return false, errors.Wrap(err, "base64.StdEncoding.DecodeString salt error")
	}
	deriveKey, err := base64.StdEncoding.DecodeString(kdfKeyStrs[2])
	if err != nil {
		return false, errors.Wrap(err, "base64.StdEncoding.DecodeString deriveKey error")
	}
	params := strings.Split(kdfKeyStrs[3], ":")
	if len(params) != 2 {
		return false, errors.New("kdfKeyStr format error, not 2 parts")
	}
	iters, err := strconv.Atoi(params[0])
	if err != nil {
		return false, errors.Wrap(err, "strconv.Atoi iters error")
	}
	keyLen, err := strconv.Atoi(params[1])
	if err != nil {
		return false, errors.Wrap(err, "strconv.Atoi keyLen error")
	}
	deriveKey2 := pbkdf2.Key(password, salt, iters, keyLen, defaultHashFunc)
	if !bytes.Equal(deriveKey, deriveKey2) {
		return false, nil
	}
	return true, nil
}

func (p *Pbkdf2Impl) GetDeriveKeyStr() string {
	// kdf key format: $argon2$salt$key$iters:keyLen
	kdfKeyStrs := make([]string, 0)
	kdfKeyStrs = append(kdfKeyStrs, p.Algorithm().String())
	encodedSalt := base64.StdEncoding.EncodeToString(p.salt)
	kdfKeyStrs = append(kdfKeyStrs, encodedSalt)
	encodedDK := base64.StdEncoding.EncodeToString(p.deriveKey)
	kdfKeyStrs = append(kdfKeyStrs, encodedDK)
	kdfKeyStrs = append(kdfKeyStrs, fmt.Sprintf("%d:%d", p.iters, p.keyLen))
	return "$" + strings.Join(kdfKeyStrs, "$")
}

func (p *Pbkdf2Impl) Algorithm() _const.Algorithm {
	return "pbkdf2"
}

func (p *Pbkdf2Impl) AlgorithmKind() _const.AlgorithmKind {
	return "kdf"
}

/**
 * @Author: xueyanghan
 * @File: argon2.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2023/9/19 14:18
 */

package kdf_impl

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
	"strconv"
	"strings"
)

type Argon2Impl struct {
	time    int
	memory  int //memory the memory parameter specifies the size of the memory in KiB
	threads int
	keyLen  int
	saltLen int

	salt      []byte
	deriveKey []byte
}

func NewArgon2Impl(time, memory, threads, keyLen, saltLen int) *Argon2Impl {
	argon2Impl := &Argon2Impl{
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
		saltLen: saltLen,
	}

	return argon2Impl
}

func (a *Argon2Impl) DeriveKeyByPassword(password string) (deriveKey []byte, err error) {
	salt := make([]byte, a.saltLen)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, errors.Wrap(err, "rand.Read failed")
	}
	a.salt = salt
	a.deriveKey = argon2.Key([]byte(password), a.salt, uint32(a.time), uint32(a.memory), uint8(a.threads), uint32(a.keyLen))
	return a.deriveKey, nil
}

func (a *Argon2Impl) VerifyDeriveKeyStr(kdfKeyStr string, password []byte) (isOk bool, err error) {
	kdfKeyStr = strings.TrimLeft(kdfKeyStr, "$")
	kdfKeyStrs := strings.Split(kdfKeyStr, "$")
	if len(kdfKeyStrs) != 4 {
		return false, errors.New("kdfKeyStr format error, not 4 parts")
	}
	if kdfKeyStrs[0] != a.Algorithm() {
		return false, errors.New("kdfKeyStr format error, not argon2")
	}
	salt, err := base64.StdEncoding.DecodeString(kdfKeyStrs[1])
	if err != nil {
		return false, errors.Wrap(err, "base64.StdEncoding.DecodeString salt failed")
	}
	deriveKey, err := base64.StdEncoding.DecodeString(kdfKeyStrs[2])
	if err != nil {
		return false, errors.Wrap(err, "base64.StdEncoding.DecodeString deriveKey failed")
	}

	params := strings.Split(kdfKeyStrs[3], ":")
	if len(params) != 4 {
		return false, errors.New("kdfKeyStr format error, not 4 params")
	}
	timeStr, memoryStr, threadsStr, keyLenStr := params[0], params[1], params[2], params[3]
	if timeStr == "" || memoryStr == "" || threadsStr == "" || keyLenStr == "" {
		return false, errors.New("kdfKeyStr format error, params is empty")
	}
	time, err := strconv.Atoi(timeStr)
	if err != nil {
		return false, errors.Wrap(err, "strconv.Atoi time failed")
	}
	memory, err := strconv.Atoi(memoryStr)
	if err != nil {
		return false, errors.Wrap(err, "strconv.Atoi memory failed")
	}
	threads, err := strconv.Atoi(threadsStr)
	if err != nil {
		return false, errors.Wrap(err, "strconv.Atoi threads failed")
	}
	keyLen, err := strconv.Atoi(keyLenStr)
	if err != nil {
		return false, errors.Wrap(err, "strconv.Atoi keyLen failed")
	}
	regenDeriveKey := argon2.Key(password, salt, uint32(time), uint32(memory), uint8(threads), uint32(keyLen))
	if !bytes.Equal(deriveKey, regenDeriveKey) {
		return false, nil
	}
	return true, nil
}

func (a *Argon2Impl) GetDeriveKeyStr() string {
	// format: $argon2$salt$key$time:memory:threads:keyLen
	kdfKeyStrs := make([]string, 0)
	kdfKeyStrs = append(kdfKeyStrs, a.Algorithm())
	encodedSalt := base64.StdEncoding.EncodeToString(a.salt)
	kdfKeyStrs = append(kdfKeyStrs, fmt.Sprintf("%s", encodedSalt))
	encodedDK := base64.StdEncoding.EncodeToString(a.deriveKey)
	kdfKeyStrs = append(kdfKeyStrs, fmt.Sprintf("%s", encodedDK))
	kdfKeyStrs = append(kdfKeyStrs, fmt.Sprintf("%d:%d:%d:%d", a.time, a.memory, a.threads, a.keyLen))
	return "$" + strings.Join(kdfKeyStrs, "$")
}

func (a *Argon2Impl) GetDeriveKey() []byte {
	return a.deriveKey
}

func (a *Argon2Impl) Algorithm() string {
	return "argon2"
}

func (a *Argon2Impl) AlgorithmKind() string {
	return "kdf"
}

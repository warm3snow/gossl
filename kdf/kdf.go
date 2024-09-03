/**
 * @Author: xueyanghan
 * @File: kdf.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 17:09
 */

package kdf

import (
	"github.com/warm3snow/gossl/kdf/kdf_impl"
)

var AlgorithmMap = map[string]interface{}{
	"argon2": &kdf_impl.Argon2Impl{},
	"pbkdf2": &kdf_impl.Pbkdf2Impl{},
	"scrypt": &kdf_impl.ScryptImpl{},
	"bcrypt": &kdf_impl.BcryptImpl{},
}

var AlgorithmKindMap = map[string][]interface{}{
	"kdf": {
		&kdf_impl.Argon2Impl{},
		&kdf_impl.Pbkdf2Impl{},
		&kdf_impl.ScryptImpl{},
		&kdf_impl.BcryptImpl{},
	},
}

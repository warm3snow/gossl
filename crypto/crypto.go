/**
 * @Author: xueyanghan
 * @File: crypto.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 17:09
 */

package crypto

import (
	"github.com/warm3snow/gossl/crypto/asym"
	"github.com/warm3snow/gossl/crypto/dgst"
	"github.com/warm3snow/gossl/crypto/sym"
)

type CryptoAlgorithm interface {
	Algorithm() string
	AlgorithmKind() string
}

var AlgorithmMap = map[string]interface{}{
	"sm4-cbc":     &sym.Sm4Cbc{},
	"aes-256-cbc": &sym.Aes256Cbc{},

	"sha256": &dgst.Sha256{},
	"sm3":    &dgst.Sm3{},

	"sm2":   &asym.Sm2WithSm3{},
	"ecdsa": &asym.EccNoHash{},
	"rsa":   &asym.RsaNoSha256{},
}

var AlgorithmKindMap = map[string][]interface{}{
	"symmetric": {
		&sym.Sm4Cbc{},
		&sym.Aes256Cbc{},
	},

	"digest": {
		&dgst.Sha256{},
		&dgst.Sm3{},
	},

	"asymmetric": {
		&asym.Sm2WithSm3{},
		&asym.EccNoHash{},
		&asym.RsaNoSha256{},
	},
}

var AlgorithmKeyGenMap = map[string]interface{}{
	"rsa":   &asym.KeyGen{},
	"sm2":   &asym.KeyGen{},
	"ecdsa": &asym.KeyGen{},

	"sm4-cbc":     &sym.KeyGen{},
	"aes-256-cbc": &sym.KeyGen{},
}
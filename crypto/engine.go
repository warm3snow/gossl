/**
 * @Author: xueyanghan
 * @File: engine.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 17:09
 */

package crypto

import "github.com/warm3snow/gossl/crypto/sym"

type CryptoAlgorithm interface {
	GetAlgorithm() string
	GetAlgorithmKind() string
}

var AlgorithmMap = map[string]interface{}{
	"sm4-cbc":     &sym.Sm4Cbc{},
	"aes-256-cbc": &sym.Aes256Cbc{},
}

var AlgorithmKindMap = map[string][]interface{}{
	"symmetric": {
		&sym.Sm4Cbc{},
		&sym.Aes256Cbc{},
	},
}

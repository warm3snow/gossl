/**
 * @Author: xueyanghan
 * @File: const.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/4 14:24
 */

package _const

type Algorithm string

func (a Algorithm) String() string {
	return string(a)
}

const (
	Sm4Cbc    Algorithm = "sm4-cbc"
	Aes256Cbc Algorithm = "aes-256-cbc"

	Sha256 Algorithm = "sha256"
	Sm3    Algorithm = "sm3"

	Sm2   Algorithm = "sm2"
	Ecdsa Algorithm = "ecdsa"
	Rsa   Algorithm = "rsa"

	X509 Algorithm = "encode"
	CSR  Algorithm = "csr"
)

type AlgorithmKind string

func (a AlgorithmKind) String() string {
	return string(a)
}

const (
	Symmetric  AlgorithmKind = "symmetric"
	Digest     AlgorithmKind = "digest"
	Asymmetric AlgorithmKind = "asymmetric"
	X509Kind   AlgorithmKind = "encode"
)

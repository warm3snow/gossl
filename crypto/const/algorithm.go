/**
 * @Author: xueyanghan
 * @File: const_debug_note.go
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

	Sm2     Algorithm = "sm2"
	Ecdsa   Algorithm = "ecdsa"
	Rsa     Algorithm = "rsa"
	Ed25519 Algorithm = "ed25519"

	X509 Algorithm = "encode"
	CSR  Algorithm = "csr"

	HashCommitment            Algorithm = "hash"
	ElGamalCommitment         Algorithm = "elgamal"
	PedersenCommitment        Algorithm = "pedersen"
	PedersenEccCommitment     Algorithm = "pedersen_ecc"
	PedersenEccNIZKCommitment Algorithm = "pedersen_ecc_nizk"
	SigmaCommitment           Algorithm = "sigma"
)

type Curve string

const (
	Sm2_curve     Curve = "sm2"
	ECC_P256      Curve = "P-256"
	ECC_P384      Curve = "P-384"
	ECC_P521      Curve = "P-521"
	Ed25519_curve Curve = "ed25519"
)

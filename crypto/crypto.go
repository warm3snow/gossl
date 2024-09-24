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
	"github.com/warm3snow/gossl/crypto/commitment"
	_const "github.com/warm3snow/gossl/crypto/const"
	"github.com/warm3snow/gossl/crypto/dgst"
	"github.com/warm3snow/gossl/crypto/sym"
	"github.com/warm3snow/gossl/crypto/x509"
)

type CryptoAlgorithm interface {
	Algorithm() _const.Algorithm
	AlgorithmKind() _const.AlgorithmKind
}

var AlgorithmMap = map[string]interface{}{
	_const.Sm4Cbc.String():    &sym.Sm4Cbc{},
	_const.Aes256Cbc.String(): &sym.Aes256Cbc{},

	_const.Sha256.String(): &dgst.Sha256{},
	_const.Sm3.String():    &dgst.Sm3{},

	_const.Sm2.String():     &asym.Sm2WithSm3{},
	_const.Ecdsa.String():   &asym.EccNoHash{},
	_const.Rsa.String():     &asym.RsaNoSha256{},
	_const.Ed25519.String(): &asym.Ed25519{},

	_const.X509.String(): &x509.X509Cert{},
	_const.CSR.String():  &x509.CSR{},

	_const.HashCommitment.String():            &commitment.HashCommitment{},
	_const.ElGamalCommitment.String():         &commitment.ElGamalCommitment{},
	_const.PedersenCommitment.String():        &commitment.PedersenCommitment{},
	_const.PedersenEccCommitment.String():     &commitment.PedersenEccCommitment{},
	_const.PedersenEccNIZKCommitment.String(): &commitment.PedersenEccNIZKCommitment{},
	_const.SigmaCommitment.String():           &commitment.SigmaCommitment{},
}

var AlgorithmKindMap = map[string][]interface{}{
	_const.Symmetric.String(): {
		&sym.Sm4Cbc{},
		&sym.Aes256Cbc{},
	},

	_const.Digest.String(): {
		&dgst.Sha256{},
		&dgst.Sm3{},
	},

	_const.Asymmetric.String(): {
		&asym.Sm2WithSm3{},
		&asym.EccNoHash{},
		&asym.RsaNoSha256{},
		&asym.Ed25519{},
	},

	_const.X509Kind.String(): {
		&x509.X509Cert{},
		&x509.CSR{},
	},

	_const.CommitmentKind.String(): {
		&commitment.HashCommitment{},
		&commitment.ElGamalCommitment{},
		&commitment.PedersenCommitment{},
		&commitment.SigmaCommitment{},
	},
}

var AlgorithmKeyGenMap = map[string]interface{}{
	_const.Rsa.String():     &asym.KeyGen{},
	_const.Sm2.String():     &asym.KeyGen{},
	_const.Ecdsa.String():   &asym.KeyGen{},
	_const.Ed25519.String(): &asym.KeyGen{},

	_const.Sm4Cbc.String():    &sym.KeyGen{},
	_const.Aes256Cbc.String(): &sym.KeyGen{},
}

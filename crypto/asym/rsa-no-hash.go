/**
 * @Author: xueyanghan
 * @File: rsa-no-hash.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/3 08:46
 */

package asym

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_const "github.com/warm3snow/gossl/crypto/const"
)

type RsaNoSha256 struct {
}

func NewRsaNoSha256() *RsaNoSha256 {
	return &RsaNoSha256{}
}

func (r *RsaNoSha256) Sign(data []byte, key *rsa.PrivateKey, signerOpts crypto.SignerOpts) ([]byte, error) {
	return key.Sign(rand.Reader, data, signerOpts)
}

func (r *RsaNoSha256) Verify(data, signature []byte, key *rsa.PublicKey, signerOpts crypto.SignerOpts) bool {
	switch signerOpts.(type) {
	case *rsa.PSSOptions:
		return rsa.VerifyPSS(key, crypto.SHA256, data, signature, signerOpts.(*rsa.PSSOptions)) == nil
	default:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, data, signature) == nil
	}
}

func (r *RsaNoSha256) Algorithm() _const.Algorithm {
	return _const.Rsa
}

func (r *RsaNoSha256) AlgorithmKind() _const.AlgorithmKind {
	return _const.Asymmetric
}

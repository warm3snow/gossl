/**
 * @Author: xueyanghan
 * @File: certificate.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/4 10:08
 */

package x509

import (
	"encoding/json"
	"encoding/pem"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/x509"
	_const "github.com/warm3snow/gossl/crypto/const"
)

type X509Cert struct {
}

func NewX509Cert() *X509Cert {
	return &X509Cert{}
}

func (x X509Cert) ParseCert(certPem string) (cert *x509.Certificate, err error) {
	certBlock, _ := pem.Decode([]byte(certPem))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("Failed to decode cert PEM")
	}

	cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to parse cert")
	}
	return cert, nil
}

func (x X509Cert) ParseCertToText(certPem string) ([]byte, error) {
	cert, err := x.ParseCert(certPem)
	if err != nil {
		return nil, err
	}
	certJson, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return nil, err
	}
	return certJson, nil
}

func (x X509Cert) Algorithm() _const.Algorithm {
	return _const.X509
}

func (x X509Cert) AlgorithmKind() _const.AlgorithmKind {
	return _const.X509Kind
}

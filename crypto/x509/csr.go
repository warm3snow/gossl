/**
 * @Author: xueyanghan
 * @File: csr.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/4 10:12
 */

package x509

import (
	"encoding/json"
	"encoding/pem"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/x509"
)

type CSR struct {
}

func NewCSR() *CSR {
	return &CSR{}
}

func (x CSR) ParseCsr(csrPem string) (csr *x509.CertificateRequest, err error) {
	csrBlock, _ := pem.Decode([]byte(csrPem))
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("Failed to decode CSR PEM")
	}

	csr, err = x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to parse CSR")
	}
	return csr, nil
}

func (x CSR) ParseCsrToText(csrPem string) ([]byte, error) {
	csr, err := x.ParseCsr(csrPem)
	if err != nil {
		return nil, err
	}
	csrJson, err := json.MarshalIndent(csr, "", "  ")
	if err != nil {
		return nil, err
	}
	return csrJson, nil
}

func (x CSR) Algorithm() string {
	return "csr"
}

func (x CSR) AlgorithmKind() string {
	return "x509"
}

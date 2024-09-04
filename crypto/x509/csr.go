/**
 * @Author: xueyanghan
 * @File: csr.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/4 10:12
 */

package x509

import (
	"bytes"
	"encoding/pem"
	"fmt"
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
	//csrJson, err := json.MarshalIndent(csr, "", "  ")
	//if err != nil {
	//	return nil, err
	//}

	return FormatCsr2Text(csr)
}

func (x CSR) Algorithm() string {
	return "csr"
}

func (x CSR) AlgorithmKind() string {
	return "x509"
}

func FormatCsr2Text(csr *x509.CertificateRequest) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("Certificate Request:\n")
	buf.WriteString("    Data:\n")
	buf.WriteString(fmt.Sprintf("        Version: %d (0x%x)\n", csr.Version, csr.Version))
	buf.WriteString(fmt.Sprintf("        Subject: %s\n", FormatPKIXName(csr.Subject)))
	buf.WriteString("        Subject Public Key Info:\n")
	buf.WriteString(fmt.Sprintf("            Public Key Algorithm: %s\n", PublicKeyAlgorithmName[int(csr.PublicKeyAlgorithm)]))

	// format public key
	FormatPKToBuffer(csr.PublicKey, &buf)

	buf.WriteString("        Attributes:\n")
	for _, attr := range csr.Attributes {
		buf.WriteString(fmt.Sprintf("            %s: %s\n", attr.Type, attr.Value))
	}
	buf.WriteString("            Requested Extensions:\n")
	for _, ext := range csr.Extensions {
		buf.WriteString(fmt.Sprintf("                %s: %s\n", ext.Id, string(ext.Value)))
	}
	buf.WriteString(fmt.Sprintf("    Signature Algorithm: %s\n", csr.SignatureAlgorithm))
	buf.WriteString("    Signature Value:\n")
	buf.WriteString(fmt.Sprintf("        %x\n", csr.Signature))

	return buf.Bytes(), nil
}

/**
 * @Author: xueyanghan
 * @File: certificate.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/4 10:08
 */

package x509

import (
	"bytes"
	"encoding/pem"
	"fmt"
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
	//certJson, err := json.MarshalIndent(cert, "", "  ")
	//if err != nil {
	//	return nil, err
	//}
	//return certJson, nil

	return FormatCert2Text(cert)
}

func (x X509Cert) Algorithm() _const.Algorithm {
	return _const.X509
}

func (x X509Cert) AlgorithmKind() _const.AlgorithmKind {
	return _const.X509Kind
}

func FormatCert2Text(cert *x509.Certificate) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("Certificate:\n")
	buf.WriteString("    Data:\n")
	buf.WriteString(fmt.Sprintf("        Version: %d (%#x)\n", cert.Version, cert.Version))
	buf.WriteString("        Serial Number:\n")
	buf.WriteString(fmt.Sprintf("            %x\n", cert.SerialNumber.Bytes()))
	buf.WriteString(fmt.Sprintf("        Signature Algorithm: %s\n", cert.SignatureAlgorithm))
	buf.WriteString(fmt.Sprintf("        Issuer: %s\n", FormatPKIXName(cert.Issuer)))
	buf.WriteString("        Validity\n")
	buf.WriteString(fmt.Sprintf("            Not Before: %s\n", cert.NotBefore))
	buf.WriteString(fmt.Sprintf("            Not After : %s\n", cert.NotAfter))
	buf.WriteString(fmt.Sprintf("        Subject: %s\n", FormatPKIXName(cert.Subject)))
	buf.WriteString("        Subject Public Key Info:\n")
	buf.WriteString(fmt.Sprintf("            Public Key Algorithm: %s\n", PublicKeyAlgorithmName[int(cert.PublicKeyAlgorithm)]))

	// format public key
	FormatPKToBuffer(cert.PublicKey, &buf)

	buf.WriteString("        X509v3 extensions:\n")
	for _, ext := range cert.Extensions {
		buf.WriteString(fmt.Sprintf("            %s: \n", OIDMapping[ext.Id.String()]))
		buf.WriteString(fmt.Sprintf("                %x\n", ext.Value))
	}
	buf.WriteString(fmt.Sprintf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm))
	buf.WriteString(fmt.Sprintf("    Signature Value:\n"))
	buf.WriteString(fmt.Sprintf("        %x\n", cert.Signature))

	return buf.Bytes(), nil
}

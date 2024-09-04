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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	_const "github.com/warm3snow/gossl/crypto/const"
	"strings"
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

	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaPubKey := cert.PublicKey.(*rsa.PublicKey)
		buf.WriteString(fmt.Sprintf("                Public-Key: (%d bit)\n", rsaPubKey.N.BitLen()))
		buf.WriteString(fmt.Sprintf("                Modulus:\n"))
		buf.WriteString(fmt.Sprintf("                    %x\n", rsaPubKey.N))
		buf.WriteString(fmt.Sprintf("                Exponent: %d (0x%x)\n", rsaPubKey.E, rsaPubKey.E))
	case *sm2.PublicKey:
		sm2PubKey := cert.PublicKey.(*sm2.PublicKey)
		buf.WriteString(fmt.Sprintf("                Public-Key: (%d bit)\n", sm2PubKey.Curve.Params().BitSize))
		keyBytes := elliptic.MarshalCompressed(sm2PubKey.Curve, sm2PubKey.X, sm2PubKey.Y)
		//keyBytes := elliptic.Marshal(sm2PubKey.Curve, sm2PubKey.X, sm2PubKey.Y)
		buf.WriteString(fmt.Sprintf("                pub: %x\n", keyBytes))
		buf.WriteString(fmt.Sprintf("                ASN1 OID: %s\n", sm2PubKey.Params().Name))
	case *ecdsa.PublicKey:
		ecdsaPubKey := cert.PublicKey.(*ecdsa.PublicKey)
		buf.WriteString(fmt.Sprintf("                Public-Key: (%d bit)\n", ecdsaPubKey.Curve.Params().BitSize))
		keyBytes := elliptic.MarshalCompressed(ecdsaPubKey.Curve, ecdsaPubKey.X, ecdsaPubKey.Y)
		buf.WriteString(fmt.Sprintf("                pub: %x\n", keyBytes))
		buf.WriteString(fmt.Sprintf("                ASN1 OID: %s\n", ecdsaPubKey.Params().Name))
	}

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

func FormatPKIXName(name pkix.Name) string {
	var buf bytes.Buffer

	for _, n := range name.Names {
		buf.WriteString(fmt.Sprintf("%s=%s, ", GetOIDName(n.Type.String()), n.Value.(string)))
	}
	for _, atv := range name.ExtraNames {
		buf.WriteString(fmt.Sprintf("%s=%s, ", GetOIDName(atv.Type.String()), atv.Value.(string)))
	}

	return strings.TrimRight(buf.String(), ", ")
}

func GetOIDName(oid string) string {
	if name, ok := OIDMapping[oid]; ok {
		return name
	}
	return oid
}

// OIDMapping 用于存储 OID 和名称的映射
var OIDMapping = map[string]string{
	"2.5.4.6":              "C",
	"2.5.4.8":              "ST",
	"2.5.4.10":             "O",
	"2.5.4.11":             "OU",
	"2.5.4.3":              "CN",
	"1.2.840.113549.1.9.1": "emailAddress",
	"2.5.29.14":            "X509v3 Subject Key Identifier",
	"2.5.29.15":            "X509v3 Key Usage",
	"2.5.29.17":            "X509v3 Subject Alt Name",
	"2.5.29.19":            "basicConstraints",
	"2.5.29.15.3":          "keyUsageDigitalSignature",
	"2.5.29.15.1":          "keyUsageContentCommitment",
	"2.5.29.15.2":          "keyUsageKeyEncipherment",
	"2.5.29.15.4":          "keyUsageDataEncipherment",
	"2.5.29.15.5":          "keyUsageKeyAgreement",
	"2.5.29.15.6":          "keyUsageKeyCertSign",
	"2.5.29.15.7":          "keyUsageCRLSign",
	"2.5.29.15.8":          "keyUsageEncipherOnly",
	"2.5.29.15.9":          "keyUsageDecipherOnly",
	"2.5.29.37":            "extendedKeyUsage",
}

var PublicKeyAlgorithmName = map[int]string{
	0: "UnknownPublicKeyAlgorithm",
	1: "RSA",
	2: "DSA",
	3: "id-ecPublicKey",
	4: "SM2",
}

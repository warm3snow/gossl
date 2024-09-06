/**
 * @Author: xueyanghan
 * @File: format.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/4 20:12
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
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"strings"
)

// formatPublicKeyModulus 格式化公钥模数
func formatBigInt(nbytes []byte) string {
	var buf bytes.Buffer
	for i := 0; i < len(nbytes); i += 16 {
		end := i + 16
		if end > len(nbytes) {
			end = len(nbytes)
		}
		buf.WriteString("                    ")
		for j := i; j < end; j++ {
			buf.WriteString(fmt.Sprintf("%x:", nbytes[j]))
		}
		buf.WriteString("\n")
	}
	return buf.String()
}

func FormatPKToBuffer(publicKey interface{}, buf *bytes.Buffer) {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		rsaPubKey := publicKey.(*rsa.PublicKey)
		buf.WriteString(fmt.Sprintf("                Public-Key: (%d bit)\n", rsaPubKey.N.BitLen()))
		buf.WriteString(fmt.Sprintf("                Modulus:\n"))
		buf.WriteString(fmt.Sprintf("                    %x\n", rsaPubKey.N))
		buf.WriteString(fmt.Sprintf("                Exponent: %d (0x%x)\n", rsaPubKey.E, rsaPubKey.E))
	case *sm2.PublicKey:
		sm2PubKey := publicKey.(*sm2.PublicKey)
		buf.WriteString(fmt.Sprintf("                Public-Key: (%d bit)\n", sm2PubKey.Curve.Params().BitSize))
		keyBytes := elliptic.MarshalCompressed(sm2PubKey.Curve, sm2PubKey.X, sm2PubKey.Y)
		//keyBytes := elliptic.Marshal(sm2PubKey.Curve, sm2PubKey.X, sm2PubKey.Y)
		buf.WriteString(fmt.Sprintf("                pub: %x\n", keyBytes))
		buf.WriteString(fmt.Sprintf("                ASN1 OID: %s\n", sm2PubKey.Params().Name))
	case *ecdsa.PublicKey:
		ecdsaPubKey := publicKey.(*ecdsa.PublicKey)
		buf.WriteString(fmt.Sprintf("                Public-Key: (%d bit)\n", ecdsaPubKey.Curve.Params().BitSize))
		keyBytes := elliptic.MarshalCompressed(ecdsaPubKey.Curve, ecdsaPubKey.X, ecdsaPubKey.Y)
		buf.WriteString(fmt.Sprintf("                pub: %x\n", keyBytes))
		buf.WriteString(fmt.Sprintf("                ASN1 OID: %s\n", ecdsaPubKey.Params().Name))
	}
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

func CertToPem(cert *x509.Certificate) []byte {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	return pem.EncodeToMemory(pemBlock)
}

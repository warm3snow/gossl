/**
 * @Author: xueyanghan
 * @File: helper.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/7 12:40
 */

package gmtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"math/big"
)

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	OidNamedCurveSm2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

func OidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	case sm2.P256Sm2():
		return OidNamedCurveSm2, true
	}
	return nil, false
}

type ECCSignature struct {
	R, S *big.Int
}

func SM2Verify(pub *sm2.PublicKey, hash, sig, uid []byte) bool {
	var sm2Sig ECCSignature
	_, err := asn1.Unmarshal(sig, &sm2Sig)
	if err != nil {
		return false
	}
	return sm2.Sm2Verify(pub, hash, uid, sm2Sig.R, sm2Sig.R)
}

func SM2Sign(priv *sm2.PrivateKey, hash, uid []byte) ([]byte, error) {
	r, s, err := sm2.Sm2Sign(priv, hash, uid, rand.Reader)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ECCSignature{r, s})
}

var versMapping = map[uint16]string{
	VersionTLS10: "TLS 1.0",
	VersionTLS11: "TLS 1.1",
	VersionTLS12: "TLS 1.2",
	VersionTLS13: "TLS 1.3",
	VersionGMSSL: "GMSSL1.1",
}

var tlsCipherSuites = map[uint16]string{
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
}

var curveMap = map[CurveID]string{
	CurveP256: "P-256",
	CurveP384: "P-384",
	CurveP521: "P-521",
	X25519:    "X25519",
}

// 创建一个 map，将签名类型映射到字符串
var signatureMap = map[uint8]string{
	signatureECDSA:    "ECDSA",
	signaturePKCS1v15: "PKCS1v15",
	signatureRSAPSS:   "RSAPSS",
	signatureSM2:      "SM2",
}

func ParseCertificate(ans1Data []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(ans1Data)
	if err != nil {
		return nil, err
	}
	switch key := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve == sm2.P256Sm2() {
			cert.PublicKey = &sm2.PublicKey{
				Curve: sm2.P256Sm2(),
				X:     key.X,
				Y:     key.Y,
			}
		}
	}
	return cert, nil
}

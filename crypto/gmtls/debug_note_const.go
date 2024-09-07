/**
 * @Author: xueyanghan
 * @File: debug_note_const.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/7 12:40
 */

package gmtls

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"github.com/tjfoc/gmsm/sm2"
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

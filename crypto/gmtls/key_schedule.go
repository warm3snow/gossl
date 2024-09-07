// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gmtls

import (
	"crypto/elliptic"
	"crypto/hmac"
	"errors"
	"hash"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)

// This file contains the functions necessary to compute the TLS 1.3 key
// schedule. See RFC 8446, Section 7.

const (
	resumptionBinderLabel         = "res binder"
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
	trafficUpdateLabel            = "traffic upd"
)

// expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) expandLabel(secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)
	n, err := hkdf.Expand(c.hash.New, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

// deriveSecret implements Derive-Secret from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = c.hash.New()
	}
	return c.expandLabel(secret, label, transcript.Sum(nil), c.hash.Size())
}

// extract implements HKDF-Extract with the cipher suite hash.
func (c *cipherSuiteTLS13) extract(newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, c.hash.Size())
	}
	return hkdf.Extract(c.hash.New, newSecret, currentSecret)
}

// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2.
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return c.expandLabel(trafficSecret, trafficUpdateLabel, nil, c.hash.Size())
}

// trafficKey generates traffic keys according to RFC 8446, Section 7.3.
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = c.expandLabel(trafficSecret, "key", nil, c.keyLen)
	iv = c.expandLabel(trafficSecret, "iv", nil, aeadNonceLength)
	return
}

// finishedHash generates the Finished verify_data or PskBinderEntry according
// to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// selection.
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
	finishedKey := c.expandLabel(baseKey, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil)
}

// exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// RFC 8446, Section 7.5.
func (c *cipherSuiteTLS13) exportKeyingMaterial(masterSecret []byte, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMasterSecret := c.deriveSecret(masterSecret, exporterLabel, transcript)
	return func(label string, context []byte, length int) ([]byte, error) {
		secret := c.deriveSecret(expMasterSecret, label, nil)
		h := c.hash.New()
		h.Write(context)
		return c.expandLabel(secret, "exporter", h.Sum(nil), length), nil
	}
}

// ecdheParameters implements Diffie-Hellman with either NIST curves or X25519,
// according to RFC 8446, Section 4.2.8.2.
type ecdheParameters interface {
	CurveID() CurveID
	PublicKey() []byte
	SharedKey(peerPublicKey []byte) []byte
	SM2SharedKey(c *Config, peerPublicKey []byte, encPubKey *sm2.PublicKey, responsor bool) []byte
}

func generateECDHEParameters(rand io.Reader, curveID CurveID) (ecdheParameters, error) {
	if curveID == X25519 {
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return nil, err
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		return &x25519Parameters{privateKey: privateKey, publicKey: publicKey}, nil
	}

	if curveID == SM2P256V1 {
		p := &nistParameters{curveID: curveID}
		privKey, err := sm2.GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		p.x, p.y = privKey.X, privKey.Y
		p.privateKey = privKey.D.Bytes()

		return p, nil
	}

	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}

	p := &nistParameters{curveID: curveID}
	var err error
	p.privateKey, p.x, p.y, err = elliptic.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func curveForCurveID(id CurveID) (elliptic.Curve, bool) {
	switch id {
	case CurveP256:
		return elliptic.P256(), true
	case CurveP384:
		return elliptic.P384(), true
	case CurveP521:
		return elliptic.P521(), true
	case SM2P256V1:
		return sm2.P256Sm2(), true
	default:
		return nil, false
	}
}

type nistParameters struct {
	privateKey []byte
	x, y       *big.Int // public key
	curveID    CurveID
}

func (p *nistParameters) CurveID() CurveID {
	return p.curveID
}

func (p *nistParameters) PublicKey() []byte {
	curve, _ := curveForCurveID(p.curveID)
	return elliptic.Marshal(curve, p.x, p.y)
}

func (p *nistParameters) SharedKey(peerPublicKey []byte) []byte {
	curve, _ := curveForCurveID(p.curveID)
	// Unmarshal also checks whether the given point is on the curve.
	x, y := elliptic.Unmarshal(curve, peerPublicKey)
	if x == nil {
		return nil
	}

	xShared, _ := curve.ScalarMult(x, y, p.privateKey)
	sharedKey := make([]byte, (curve.Params().BitSize+7)>>3)
	xBytes := xShared.Bytes()
	copy(sharedKey[len(sharedKey)-len(xBytes):], xBytes)

	return sharedKey
}

func (p *nistParameters) SM2SharedKey(c *Config, peerPublicKey []byte, pEncPubKey *sm2.PublicKey, responsor bool) []byte {
	curve := sm2.P256Sm2()
	x, y := elliptic.Unmarshal(curve, peerPublicKey)
	if x == nil {
		return nil
	}

	sm2Params := curve.Params()
	// Calculate w
	curveN := sm2Params.N
	// w := math.Ceil(math.Log2(fN)/2) - 1
	w := big.NewInt(int64((curveN.BitLen()+1)/2 - 1))
	var w2Pow, xSub, xs, xp, xAnd, pxAnd big.Int

	// Calculate 2 ^ w
	w2Pow.Exp(big.NewInt(2), w, nil)
	// 2 ^ w - 1
	xSub.Sub(&w2Pow, big.NewInt(1))
	// peerPubKey & (2 ^ w - 1)
	pxAnd.And(x, &xSub)
	// peer x =  2 ^ w + (selfPubKey & (2 ^ w - 1))
	xp.Add(&w2Pow, &pxAnd)

	// selfPubKey & (2 ^ w - 1)
	xAnd.And(p.x, &xSub)
	// self x =  2 ^ w + (peerPubKey & (2 ^ w - 1))
	xs.Add(&w2Pow, &xAnd)

	// self encCert privateKey
	if len(c.Certificates) < 2 {
		panic("GMTLS1.1 ECDHE mode requires 2 gm certificates")
	}
	sEncPrivKey, ok := c.Certificates[1].PrivateKey.(*sm2.PrivateKey)
	if !ok {
		return nil
	}
	// self encCert publicKey
	sEncPubKey := sEncPrivKey.PublicKey
	// self random number
	privKeyD := new(big.Int).SetBytes(p.privateKey)

	var tB, xMul, h, htB big.Int
	// xs + self random
	xMul.Mul(&xs, privKeyD)
	// tB = (self encPrivKey + xs * self random)
	tB.Add(sEncPrivKey.D, &xMul)

	// h = #E(Fq)/n
	h.Div(sm2Params.P, sm2Params.N)
	// [xp] * peer pubKey
	x1RAx, x1RAy := curve.ScalarMult(x, y, xp.Bytes())
	// Pa + [x1]Ra : peer encPubKey + [xp] * peer pubKey
	prx, pry := curve.Add(pEncPubKey.X, pEncPubKey.Y, x1RAx, x1RAy)
	// h * tB
	htB.Mul(&h, &tB)

	// Calculate U or V
	UVx, UVy := curve.ScalarMult(prx, pry, htB.Bytes())
	// Calculate Za for self pubKey, Zb for peer pubKey
	Za := make([]byte, 0)
	Zb := make([]byte, 0)
	// responsor true represents client
	if responsor {
		Za, _ = sm2.ZA(pEncPubKey, []byte(""))
		Zb, _ = sm2.ZA(&sEncPubKey, []byte(""))
	} else {
		Za, _ = sm2.ZA(&sEncPubKey, []byte(""))
		Zb, _ = sm2.ZA(pEncPubKey, []byte(""))
	}

	//sharedBuf = (UVx || UVy || Za || Zb)
	pointlen := (curve.Params().BitSize + 7) >> 3
	sharedBuf := make([]byte, pointlen*2+32*2)
	xBytes := UVx.Bytes()
	copy(sharedBuf[pointlen-len(xBytes):], xBytes)
	yBytes := UVy.Bytes()
	copy(sharedBuf[pointlen*2-len(yBytes):], yBytes)
	copy(sharedBuf[pointlen*2:], Za)
	copy(sharedBuf[pointlen*2+32:], Zb)
	// 48 bytes shared key
	sharedKey := kdf_gmt003_2012(sharedBuf, 48)
	return sharedKey
}

// GM/T003_2012 Defined Key Derive Function
func kdf_gmt003_2012(sharedBuf []byte, klen int) []byte {
	ctx := sm3.New()
	ctr := make([]byte, 4)
	ctxlen := 32
	outlen := klen
	K := make([]byte, 0)

	for counter := 1; ; counter++ {
		ctr[0] = byte((counter >> 24) & 0xFF)
		ctr[1] = byte((counter >> 16) & 0xFF)
		ctr[2] = byte((counter >> 8) & 0xFF)
		ctr[3] = byte(counter & 0xFF)

		ctx.Write(sharedBuf)
		ctx.Write(ctr)
		digest := ctx.Sum(nil)

		if outlen > ctxlen {
			K = append(K, digest...)
			outlen -= ctxlen
		} else {
			K = append(K, digest[:outlen]...)
			break
		}
		ctx.Reset()
	}
	return K
}

type x25519Parameters struct {
	privateKey []byte
	publicKey  []byte
}

func (p *x25519Parameters) CurveID() CurveID {
	return X25519
}

func (p *x25519Parameters) PublicKey() []byte {
	return p.publicKey[:]
}

func (p *x25519Parameters) SharedKey(peerPublicKey []byte) []byte {
	sharedKey, err := curve25519.X25519(p.privateKey, peerPublicKey)
	if err != nil {
		return nil
	}
	return sharedKey
}

func (p *x25519Parameters) SM2SharedKey(c *Config, peerPublicKey []byte, encPubKey *sm2.PublicKey, responsor bool) []byte {
	panic("X25519 should not call this function")
}

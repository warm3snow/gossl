// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gmtls

import (
	"bytes"
	gocrypto "crypto"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/warm3snow/gossl/crypto"
	"io"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// ecdheKeyAgreementGM implements a TLS key agreement where the server
// generates an ephemeral SM2 public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH.
type ecdheKeyAgreementGM struct {
	version uint16
	isRSA   bool
	params  ecdheParameters

	// ckx and preMasterSecret are generated in processServerKeyExchange
	// and returned in generateClientKeyExchange.
	ckx             *clientKeyExchangeMsg
	preMasterSecret []byte
}

func (ka *ecdheKeyAgreementGM) generateServerKeyExchange(config *Config, signCert, cipherCert *Certificate,
	clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	var curveID CurveID
	for _, c := range clientHello.supportedCurves {
		if config.supportsCurve(c) {
			curveID = c
			break
		}
	}

	if curveID == 0 {
		//return nil, errors.New("tls: no supported elliptic curves offered")
		// No supportedCurves from TASSL clientHello, set curveID = SM2P256V1
		curveID = SM2P256V1
	}
	if _, ok := curveForCurveID(curveID); curveID != SM2P256V1 && !ok {
		return nil, errors.New("tls: CurvePreferences includes unsupported curve")
	}

	params, err := generateECDHEParameters(config.rand(), curveID)
	if err != nil {
		return nil, err
	}
	ka.params = params

	// See RFC 4492, Section 5.4.
	ecdhePublic := params.PublicKey()
	serverECDHEParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHEParams[0] = 3 // named curve
	serverECDHEParams[1] = byte(curveID >> 8)
	serverECDHEParams[2] = byte(curveID)
	serverECDHEParams[3] = byte(len(ecdhePublic))
	copy(serverECDHEParams[4:], ecdhePublic)

	priv, ok := signCert.PrivateKey.(gocrypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tls: certificate private key of type %T does not implement crypto.Signer", signCert.PrivateKey)
	}

	var sigType uint8
	var sigHash crypto.Hash
	sigType, sigHash, err = typeAndHashFromSignatureScheme(SM2WithSM3)
	if err != nil {
		return nil, err
	}

	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, hello.random, serverECDHEParams)

	signOpts := gocrypto.SignerOpts(gocrypto.Hash(sigHash))

	sig, err := priv.Sign(config.rand(), signed, signOpts)
	if err != nil {
		return nil, errors.New("tls: failed to sign ECDHE parameters: " + err.Error())
	}

	skx := new(serverKeyExchangeMsg)

	skx.key = make([]byte, len(serverECDHEParams)+2+len(sig))
	copy(skx.key, serverECDHEParams)
	k := skx.key[len(serverECDHEParams):]
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)

	return skx, nil
}

func (ka *ecdheKeyAgreementGM) processClientKeyExchange(config *Config, cert *Certificate, peerPubKey gocrypto.PublicKey, ckx *clientKeyExchangeMsg, version uint16, responsor bool) ([]byte, error) {
	// TASSL client key exchange prefix [3, 0, 0]
	// if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
	// 	return nil, errClientKeyExchange
	// }

	encPubKey, ok := peerPubKey.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("tls: SM2SharedKey requires a sm2 public key")
	}
	preMasterSecret := ka.params.SM2SharedKey(config, ckx.ciphertext[4:], encPubKey, responsor)
	if preMasterSecret == nil {
		return nil, errClientKeyExchange
	}

	return preMasterSecret, nil
}

func (ka *ecdheKeyAgreementGM) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert, encCert *x509.Certificate, skx *serverKeyExchangeMsg, responsor bool) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	curveID := CurveID(skx.key[1])<<8 | CurveID(skx.key[2])

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	serverECDHEParams := skx.key[:4+publicLen]
	publicKey := serverECDHEParams[4:]

	sig := skx.key[4+publicLen:]
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	if _, ok := curveForCurveID(curveID); curveID != SM2P256V1 && !ok {
		// return errors.New("tls: server selected unsupported curve")
		// no curveID sent from TASSL
		curveID = SM2P256V1
	}

	params, err := generateECDHEParameters(config.rand(), curveID)
	if err != nil {
		return err
	}
	ka.params = params

	encPubKey, ok := encCert.PublicKey.(*sm2.PublicKey)
	if !ok {
		return errors.New("tls: SM2SharedKey requires a sm2 public key")
	}
	ka.preMasterSecret = params.SM2SharedKey(config, publicKey, encPubKey, responsor)
	if ka.preMasterSecret == nil {
		return errServerKeyExchange
	}

	ourPublicKey := params.PublicKey()
	ka.ckx = new(clientKeyExchangeMsg)
	ka.ckx.ciphertext = make([]byte, 1+2+1+len(ourPublicKey))
	ka.ckx.ciphertext[0] = 3
	ka.ckx.ciphertext[1] = 0
	ka.ckx.ciphertext[2] = 0
	ka.ckx.ciphertext[3] = byte(len(ourPublicKey))
	copy(ka.ckx.ciphertext[4:], ourPublicKey)

	var sigType uint8
	var sigHash crypto.Hash
	sigType, sigHash, err = typeAndHashFromSignatureScheme(SM2WithSM3)
	if err != nil {
		return err
	}

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	sig = sig[2:]

	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, serverHello.random, serverECDHEParams)
	if err := verifyHandshakeSignature(sigType, cert.PublicKey, gocrypto.Hash(sigHash), signed, sig); err != nil {
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}
	return nil
}

func (ka *ecdheKeyAgreementGM) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}

	return ka.preMasterSecret, ka.ckx, nil
}

// eccKeyAgreementGM implements a TLS key agreement where the server
// generates an ephemeral SM2 public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH.
type eccKeyAgreementGM struct {
	version    uint16
	privateKey []byte
	curveid    CurveID

	// publicKey is used to store the peer's public value when X25519 is
	// being used.
	publicKey []byte
	// x and y are used to store the peer's public value when one of the
	// NIST curves is being used.
	x, y *big.Int

	//cert for encipher referred to GMT0024
	encipherCert *x509.Certificate
}

func (ka *eccKeyAgreementGM) generateServerKeyExchange(config *Config, signCert, cipherCert *Certificate,
	clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	// mod by syl only one cert
	//digest := ka.hashForServerKeyExchange(clientHello.random, hello.random, cert.Certificate[1])
	digest := ka.hashForServerKeyExchange(clientHello.random, hello.random, cipherCert.Certificate[0])

	priv, ok := signCert.PrivateKey.(gocrypto.Signer)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Signer")
	}
	sig, err := priv.Sign(config.rand(), digest, gocrypto.SignerOpts(gocrypto.Hash(crypto.SM3)))
	if err != nil {
		return nil, err
	}

	len := len(sig)

	ske := new(serverKeyExchangeMsg)
	ske.key = make([]byte, len+2)
	ske.key[0] = byte(len >> 8)
	ske.key[1] = byte(len)
	copy(ske.key[2:], sig)

	return ske, nil
}

func (ka *eccKeyAgreementGM) processClientKeyExchange(config *Config, cert *Certificate, peerPubKey gocrypto.PublicKey, ckx *clientKeyExchangeMsg, version uint16, responsor bool) ([]byte, error) {
	if len(ckx.ciphertext) == 0 {
		return nil, errClientKeyExchange
	}

	if int(ckx.ciphertext[0]<<8|ckx.ciphertext[1]) != len(ckx.ciphertext)-2 {
		return nil, errClientKeyExchange
	}

	cipher := ckx.ciphertext[2:]

	decrypter, ok := cert.PrivateKey.(gocrypto.Decrypter)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Decrypter")
	}

	cipher, err := sm2.CipherUnmarshal(cipher)
	if err != nil {
		return nil, err
	}
	plain, err := decrypter.Decrypt(config.rand(), cipher, nil)
	if err != nil {
		return nil, err
	}

	if len(plain) != 48 {
		return nil, errClientKeyExchange
	}

	//we do not examine the version here according to openssl practice
	return plain, nil
}

func (ka *eccKeyAgreementGM) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert, encCert *x509.Certificate, skx *serverKeyExchangeMsg, responsor bool) error {
	if len(skx.key) <= 2 {
		return errServerKeyExchange
	}
	sigLen := int(skx.key[0]<<8 | skx.key[1])
	if sigLen+2 != len(skx.key) {
		return errServerKeyExchange
	}
	sig := skx.key[2:]
	//sig := skx.key[:]

	digest := ka.hashForServerKeyExchange(clientHello.random, serverHello.random, ka.encipherCert.Raw)

	//verify
	pubKey, ok := cert.PublicKey.(*sm2.PublicKey)
	if !ok {
		return errors.New("tls: sm2 signing requires a sm2 public key")
	}

	ecdsaSig := new(ecdsaSignature)
	rest, err := asn1.Unmarshal(sig, ecdsaSig)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("tls:processServerKeyExchange: sm2 get signature failed")
	}
	if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
		return errors.New("tls: processServerKeyExchange: sm2 signature contained zero or negative values")
	}

	if !pubKey.Verify(digest, sig) {
		return errors.New("tls: processServerKeyExchange: sm2 verification failure")
	}

	return nil
}

func (ka eccKeyAgreementGM) hashForServerKeyExchange(slices ...[]byte) []byte {
	buffer := new(bytes.Buffer)
	for i, slice := range slices {
		if i == 2 {
			buffer.Write([]byte{byte(len(slice) >> 16), byte(len(slice) >> 8), byte(len(slice))})
		}
		buffer.Write(slice)
	}
	return buffer.Bytes()
}

func (ka *eccKeyAgreementGM) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}
	pubKey := ka.encipherCert.PublicKey.(*sm2.PublicKey)
	encrypted, err := sm2.Encrypt(pubKey, preMasterSecret, config.rand(), sm2.C1C3C2)
	if err != nil {
		return nil, nil, err
	}
	// GMT0024 通信时密文采用 GMT009 ASN1方式组织
	encrypted, err = sm2.CipherMarshal(encrypted)
	if err != nil {
		return nil, nil, err
	}
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(len(encrypted) >> 8)
	ckx.ciphertext[1] = byte(len(encrypted))
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}

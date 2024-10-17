/**
 * @Author: xueyanghan
 * @File: encode.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/2 19:35
 */

package utils

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

func Hex2Bytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

func Bytes2Hex(b []byte) string {
	return hex.EncodeToString(b)
}

func KeyFile2PrivateKey(keyFile string) (any, error) {
	keyPem, err := ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return KeyPem2PrivateKey(keyPem)
}

func KeyFile2PublicKey(keyFile string) (any, error) {
	keyPem, err := ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return KeyPem2PublicKey(keyPem)
}

// HashPointToPrivateKey hashes a point on the elliptic curve and derives a private key
func HashPointToPrivateKey(curve elliptic.Curve, pointX, pointY *big.Int) *big.Int {
	// Hash the point using SHA-256
	h := sha256.New()
	h.Write(pointX.Bytes())
	h.Write(pointY.Bytes())
	hashed := h.Sum(nil)

	// Convert the hash to a private key (big.Int)
	privateKey := new(big.Int).SetBytes(hashed)

	// Ensure the private key is within the valid range
	privateKey.Mod(privateKey, curve.Params().N)

	return privateKey
}

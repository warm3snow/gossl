/**
 * @Author: xueyanghan
 * @File: ring_signature.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/10/17 16:30
 */

package ring_signature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/warm3snow/gossl/utils"
	"math/big"
)

type RingSignature struct {
}

type Signature struct {
	I  *ecdsa.PublicKey `json:"I"`  // key image
	C  []*big.Int       `json:"C"`  // {c1, c2, ..., cn}
	RR []*big.Int       `json:"RR"` // {r1, r2, ..., rn}
}

func NewRingSignature() *RingSignature {
	return &RingSignature{}
}

func (rs *RingSignature) KeyGen(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	xs, _ := ecdsa.GenerateKey(curve, rand.Reader)

	// I = xs * H(Ps)
	HpPs := utils.HashPointToPublicKey(curve, xs.X, xs.Y)
	Ix, Iy := curve.ScalarMult(HpPs.X, HpPs.Y, xs.D.Bytes())
	I := &ecdsa.PublicKey{
		Curve: curve,
		X:     Ix,
		Y:     Iy,
	}

	return xs, I
}

func (rs *RingSignature) Sign(xs *ecdsa.PrivateKey, msg []byte, P []*ecdsa.PublicKey, I *ecdsa.PublicKey) (*Signature, error) {
	var err error

	N := xs.Curve.Params().N
	curve := xs.Curve

	// Step 1: Generate random list Q and W
	ringSize := len(P)
	Q := make([]*big.Int, ringSize)
	W := make([]*big.Int, ringSize)
	for i := 0; i < ringSize; i++ {
		Q[i], err = rand.Int(rand.Reader, N)
		if err != nil {
			return nil, err
		}
		W[i], err = rand.Int(rand.Reader, N)
		if err != nil {
			return nil, err
		}
	}

	// Step 2: Calculate L and R
	L := make([]*ecdsa.PublicKey, ringSize)
	R := make([]*ecdsa.PublicKey, ringSize)
	Ps := elliptic.MarshalCompressed(curve, xs.X, xs.Y)
	PsIndex := -1
	for i := 0; i < ringSize; i++ {
		Pi := elliptic.MarshalCompressed(curve, P[i].X, P[i].Y)

		L[i], R[i] = &ecdsa.PublicKey{}, &ecdsa.PublicKey{}
		L[i].X, L[i].Y = curve.ScalarBaseMult(Q[i].Bytes())
		HpPi := utils.HashPointToPublicKey(curve, P[i].X, P[i].Y)
		R[i].X, R[i].Y = curve.ScalarMult(HpPi.X, HpPi.Y, Q[i].Bytes())
		// i != s
		if !bytes.Equal(Pi, Ps) {
			wPx, wPy := curve.ScalarMult(P[i].X, P[i].Y, W[i].Bytes())
			wIx, wIy := curve.ScalarMult(I.X, I.Y, W[i].Bytes())
			L[i].X, L[i].Y = curve.Add(L[i].X, L[i].Y, wPx, wPy)
			R[i].X, R[i].Y = curve.Add(R[i].X, R[i].Y, wIx, wIy)
		} else {
			PsIndex = i
		}
	}

	// Step 3: Calculate c
	LBytes := make([]byte, ringSize)
	RBytes := make([]byte, ringSize)
	for i := 0; i < ringSize; i++ {
		LBytes = append(LBytes, elliptic.MarshalCompressed(curve, L[i].X, L[i].Y)...)
		RBytes = append(RBytes, elliptic.MarshalCompressed(curve, R[i].X, R[i].Y)...)

		fmt.Printf("L[%d]: %s\n", i, hex.EncodeToString(elliptic.MarshalCompressed(curve, L[i].X, L[i].Y)))
		fmt.Printf("R[%d]: %s\n", i, hex.EncodeToString(elliptic.MarshalCompressed(curve, R[i].X, R[i].Y)))
	}
	mLRBytes := append(msg, LBytes...)
	mLRBytes = append(mLRBytes, RBytes...)
	mLRBytesSha256 := sha256.Sum256(mLRBytes)
	c := new(big.Int).SetBytes(mLRBytesSha256[:])
	fmt.Printf("L: %s\n", hex.EncodeToString(LBytes))
	fmt.Printf("R: %s\n", hex.EncodeToString(RBytes))
	fmt.Printf("c: %s\n", c.String())

	// Step 4: Calculate {c1, c2, ..., cn} and {r1, r2, ..., rn}
	cSlice := make([]*big.Int, ringSize)
	rSlice := make([]*big.Int, ringSize)

	for i := 0; i < ringSize; i++ {
		cSlice[i] = W[i]
		rSlice[i] = Q[i]
	}

	sumCWithoutPs := new(big.Int)
	for i := 0; i < ringSize; i++ {
		if i != PsIndex {
			sumCWithoutPs.Add(sumCWithoutPs, cSlice[i])
		}
	}
	cSlice[PsIndex] = new(big.Int).Mod(new(big.Int).Sub(c, sumCWithoutPs), N)
	rSlice[PsIndex] = new(big.Int).Mod(new(big.Int).Sub(Q[PsIndex], new(big.Int).Mul(cSlice[PsIndex], xs.D)), N)

	var sumC = new(big.Int)
	for i := 0; i < ringSize; i++ {
		sumC.Add(sumC, cSlice[i])
	}

	return &Signature{I: I, C: cSlice, RR: rSlice}, nil
}

func (rs *RingSignature) Verify(msg []byte, P []*ecdsa.PublicKey, signature *Signature) bool {
	// Step 1: re-Calculate L and R
	curve := signature.I.Curve
	ringSize := len(P)

	L := make([]*ecdsa.PublicKey, ringSize)
	R := make([]*ecdsa.PublicKey, ringSize)
	for i := 0; i < ringSize; i++ {
		L[i], R[i] = &ecdsa.PublicKey{}, &ecdsa.PublicKey{}

		L[i].X, L[i].Y = curve.ScalarBaseMult(signature.RR[i].Bytes())
		cPx, cPy := curve.ScalarMult(P[i].X, P[i].Y, signature.C[i].Bytes())
		L[i].X, L[i].Y = curve.Add(L[i].X, L[i].Y, cPx, cPy)

		hpG := utils.HashPointToPublicKey(curve, P[i].X, P[i].Y)
		rHpGx, rHpGy := curve.ScalarMult(hpG.X, hpG.Y, signature.RR[i].Bytes())
		cIx, cIy := curve.ScalarMult(signature.I.X, signature.I.Y, signature.C[i].Bytes())
		R[i].X, R[i].Y = curve.Add(rHpGx, rHpGy, cIx, cIy)

		fmt.Printf("L'[%d]: %s\n", i, hex.EncodeToString(elliptic.MarshalCompressed(curve, L[i].X, L[i].Y)))
		fmt.Printf("R'[%d]: %s\n", i, hex.EncodeToString(elliptic.MarshalCompressed(curve, R[i].X, R[i].Y)))
	}

	// Step2: Calculate sum of ci
	sumC := new(big.Int)
	for i := 0; i < ringSize; i++ {
		sumC.Add(sumC, signature.C[i])
	}
	sumC.Mod(sumC, curve.Params().N)
	fmt.Printf("sumC: %s\n", sumC.String())

	// Step3: re-Calculate c
	LBytes := make([]byte, ringSize)
	RBytes := make([]byte, ringSize)
	for i := 0; i < ringSize; i++ {
		LBytes = append(LBytes, elliptic.MarshalCompressed(curve, L[i].X, L[i].Y)...)
		RBytes = append(RBytes, elliptic.MarshalCompressed(curve, R[i].X, R[i].Y)...)
	}
	mLRBytes := append(msg, LBytes...)
	mLRBytes = append(mLRBytes, RBytes...)
	mLRBytesSha256 := sha256.Sum256(mLRBytes)
	c := new(big.Int).SetBytes(mLRBytesSha256[:])

	fmt.Printf("L: %s\n", hex.EncodeToString(LBytes))
	fmt.Printf("R: %s\n", hex.EncodeToString(RBytes))
	fmt.Printf("c: %s\n", c.String())

	return c.Cmp(sumC) == 0
}

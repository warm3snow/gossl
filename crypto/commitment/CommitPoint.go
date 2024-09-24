/**
 * @Author: xueyanghan
 * @File: Point.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 16:20
 */

package commitment

import (
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"strings"
)

type Point struct {
	X, Y []byte
}

func (p *Point) String() string {
	return hex.EncodeToString(p.X) + "||" + hex.EncodeToString(p.Y)
}

func (p *Point) FromString(s string) *Point {
	split := strings.Split(s, "||")
	p.X, _ = hex.DecodeString(split[0])
	p.Y, _ = hex.DecodeString(split[1])
	return p
}

func PointToBytes(p *Point, curve elliptic.Curve) []byte {
	if p == nil || p.X == nil || p.Y == nil {
		return []byte{0x00} // 0x00 means ∞
	}
	return elliptic.MarshalCompressed(curve,
		new(big.Int).SetBytes(p.X),
		new(big.Int).SetBytes(p.Y))
}

func PointNegate(p *Point, curve elliptic.Curve) *Point {
	if p == nil || p.X == nil || p.Y == nil {
		return nil
	}
	// y = -y mod p
	//The inverse of a point 𝑃=(𝑥𝑃,𝑦𝑃) is its reflexion across the x-axis: 𝑃′=(𝑥𝑃,−𝑦𝑃)
	//must -yP be taken mod P
	y := new(big.Int).Sub(big.NewInt(0), new(big.Int).SetBytes(p.Y))
	y = new(big.Int).Mod(y, curve.Params().P)

	return &Point{X: p.X, Y: y.Bytes()}
}

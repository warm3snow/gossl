/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package commitment

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto/commitment"
	_const "github.com/warm3snow/gossl/crypto/const"
	"strings"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "verify the cryptographic commitment",
	Long:  `verify allows one to verify the commitment against the openings`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runVerify(cmd, args); err != nil {
			panic(err)
		}
	},
}

func init() {
	commitmentCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	verifyCmd.PersistentFlags().StringVar(&C, "C", "", "commitment of the chosen value")
	verifyCmd.PersistentFlags().StringVar(&x, "x", "", "opening of commitment, such as m/e/x")
	verifyCmd.PersistentFlags().StringVar(&y, "y", "", "opening of commitment, such as r/z/y")
	verifyCmd.PersistentFlags().StringVar(&proof, "proof", "", "proof of commitment, only for nizk commitment")
}

var (
	x     string
	y     string
	C     string
	proof string
)

func runVerify(cmd *cobra.Command, args []string) error {
	algo := cmd.Flag("algo").Value.String()
	if algo == "" {
		return errors.New("algorithm is required")
	}
	var (
		xBytes, yBytes []byte
		cBytes         []byte
		cPoint         *commitment.Point
		proofPoint     *commitment.Point
	)
	x, y = cmd.Flag("x").Value.String(), cmd.Flag("y").Value.String()
	if x == "" || y == "" {
		return errors.New("opening of commitment is required")
	} else {
		xBytes, _ = hex.DecodeString(x)
		yBytes, _ = hex.DecodeString(y)
	}
	C = cmd.Flag("C").Value.String()
	if C == "" {
		return errors.New("commitment C is required")
	} else {
		if strings.Contains(C, "||") {
			cPoint = &commitment.Point{}
			cPoint.FromString(C)
		} else {
			cBytes, _ = hex.DecodeString(C)
		}
	}
	proof = cmd.Flag("proof").Value.String()
	if proof != "" {
		proofPoint = &commitment.Point{}
		proofPoint.FromString(proof)
	}

	var (
		verifyOK bool
	)
	// verify the commitment
	switch algo {
	case _const.HashCommitment.String():
		cc := commitment.NewHashCommitment(sha256.New())
		verifyOK = cc.Verify(cBytes, xBytes, yBytes)
	case _const.ElGamalCommitment.String():
	//cc := commitment.NewElGamalCommitment(1024)
	case _const.PedersenCommitment.String():
	//cc := commitment.NewPedersenCommitment(1024)
	case _const.PedersenEccCommitment.String():
	//cc := commitment.NewPedersenEccCommitment(elliptic.P256())
	case _const.PedersenEccNIZKCommitment.String():
	//cc := commitment.NewPedersenEccNIZKCommitment(elliptic.P256())
	case _const.SigmaCommitment.String():
		cc := commitment.NewSigmaEccNIZKCommitment(elliptic.P256())
		verifyOK = cc.Verify(cPoint, xBytes, yBytes)
	default:
		return errors.New("unsupported algorithm")
	}

	if verifyOK {
		cmd.Println("commitment is verified successfully")
	}

	return nil
}

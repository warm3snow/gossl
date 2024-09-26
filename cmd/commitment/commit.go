/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package commitment

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto/commitment"
	_const "github.com/warm3snow/gossl/crypto/const"
	"github.com/warm3snow/gossl/utils"
)

// commitCmd represents the commit command
var commitCmd = &cobra.Command{
	Use:   "commit",
	Short: "commit and open of cryptographic commitment",
	Long: `commit of cryptographic commitment allows one to 
commit to a chosen value (or chosen statement)`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runCommit(cmd, args); err != nil {
			panic(err)
		}
	},
}

func init() {
	commitmentCmd.AddCommand(commitCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// commitCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// commitCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runCommit(cmd *cobra.Command, args []string) error {
	algo := cmd.Flag("algo").Value.String()
	if algo == "" {
		return errors.New("algorithm is required")
	}
	inText := cmd.Flag("in-text").Value.String()
	if inText == "" {
		in := cmd.Flag("in").Value.String()
		if in == "" {
			return errors.New("input text is required")
		}
		inBytes, err := utils.ReadFile(in)
		if err != nil {
			return err
		}
		inText = string(inBytes)
	}

	var (
		// common params
		g, h, p string

		// commitments
		C      []byte
		CPoint *commitment.Point

		// openings
		m, r  []byte
		x, y  []byte
		proof *commitment.Point
		e, z  []byte

		err error
	)
	var rBytes [32]byte
	_, err = rand.Read(rBytes[:])
	if err != nil {
		return errors.Wrap(err, "generate random r failed")
	}

	switch algo {
	case _const.HashCommitment.String():
		cc := commitment.NewHashCommitment(sha256.New())
		C = cc.Commit([]byte(inText), nil)
		m, r = cc.Open()
	case _const.ElGamalCommitment.String():
		r = rBytes[:]
		cc := commitment.NewElGamalCommitment(1024)
		CPoint = cc.Commit([]byte(inText), r)
		m, r = cc.Open()
		g, h, p = cc.GetCommonParams()
	case _const.PedersenCommitment.String():
		r = rBytes[:]
		cc := commitment.NewPedersenCommitment(1024)
		C = cc.Commit([]byte(inText), r)
		m, r = cc.Open()
		g, h, p = cc.GetCommonParams()
	case _const.PedersenEccCommitment.String():
		r = rBytes[:]
		cc := commitment.NewPedersenEccCommitment(elliptic.P256())
		CPoint = cc.Commit([]byte(inText), r)
		m, r = cc.Open()
		g, h = cc.GetCommonParams()
	case _const.PedersenEccNIZKCommitment.String():
		cc := commitment.NewPedersenEccNIZKCommitment(elliptic.P256())
		CPoint = cc.Commit([]byte(inText), rBytes[:])
		proof, x, y = cc.Open()
		g, h = cc.GetCommonParams()
	case _const.SigmaCommitment.String():
		cc := commitment.NewSigmaEccNIZKCommitment(elliptic.P256())
		CPoint = cc.Commit([]byte(inText), nil)
		e, z = cc.Open()
		g = cc.GetCommonParams()
	default:
		return errors.New("unsupported algorithm")
	}

	fmt.Printf("Common Params: \n")
	if g != "" {
		cmd.Println("\tg:", g)
	}
	if h != "" {
		cmd.Println("\th:", h)
	}
	if p != "" {
		cmd.Println("\tp:", p)
	}

	fmt.Printf("Commitments: \n")
	if C != nil {
		cmd.Println("\tC:", hex.EncodeToString(C))
	}
	if CPoint != nil {
		cmd.Println("\tC:", CPoint)
	}

	fmt.Printf("Openings: \n")
	if m != nil {
		cmd.Println("\tm:", hex.EncodeToString(m))
	}
	if r != nil {
		cmd.Println("\tr:", hex.EncodeToString(r))
	}
	if x != nil {
		cmd.Println("\tx:", hex.EncodeToString(x))
		cmd.Println("\ty:", hex.EncodeToString(y))
	}
	if e != nil {
		cmd.Println("\te:", hex.EncodeToString(e))
		cmd.Println("\tz:", hex.EncodeToString(z))
	}
	if proof != nil {
		cmd.Println("\tproof:", proof)
	}

	return nil
}

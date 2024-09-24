/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package commitment

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto/commitment"
	_const "github.com/warm3snow/gossl/crypto/const"
)

// commitCmd represents the commit command
var commitCmd = &cobra.Command{
	Use:   "commit",
	Short: "commit phase of cryptographic commitment",
	Long: `commit phase of cryptographic commitment allows one to 
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
		return errors.New("input text is required")
	}
	verbose, _ := cmd.Flags().GetBool("verbose")

	var (
		C      []byte
		CPoint *commitment.Point
		err    error
	)
	var r [32]byte
	_, err = rand.Read(r[:])
	if err != nil {
		return errors.Wrap(err, "generate random r failed")
	}

	switch algo {
	case _const.HashCommitment.String():
		cc := commitment.NewHashCommitment(sha256.New())
		C = cc.Commit([]byte(inText), r[:])
	case _const.ElGamalCommitment.String():
		cc := commitment.NewElGamalCommitment(1024)
		CPoint = cc.Commit([]byte(inText), r[:])
	case _const.PedersenCommitment.String():
		cc := commitment.NewPedersenCommitment(1024)
		C = cc.Commit([]byte(inText), r[:])
	case _const.PedersenEccCommitment.String():
		cc := commitment.NewPedersenEccCommitment(elliptic.P256())
		CPoint = cc.Commit([]byte(inText), r[:])
	case _const.PedersenEccNIZKCommitment.String():
		cc := commitment.NewPedersenEccNIZKCommitment(elliptic.P256())
		CPoint = cc.Commit([]byte(inText), r[:])
	case _const.SigmaCommitment.String():
		cc := commitment.NewSigmaEccNIZKCommitment(elliptic.P256())
		CPoint = cc.Commit([]byte(inText), r[:])
	default:
		return errors.New("unsupported algorithm")
	}

	if verbose {
		cmd.Println("m:", inText)
		cmd.Println("r:", hex.EncodeToString(r[:]))
	}
	if C != nil {
		cmd.Println("C:", hex.EncodeToString(C))
	}
	if CPoint != nil {
		cmd.Println("CPoint:", CPoint)
	}

	return nil
}

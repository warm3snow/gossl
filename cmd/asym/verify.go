/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package asym

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/warm3snow/gossl/crypto/asym"
	cdgst "github.com/warm3snow/gossl/crypto/dgst"
	"github.com/warm3snow/gossl/utils"
	"os"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "verify a signature",
	Long:  `verify a signature with specified asymmetric algorithm and public key.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runVerify(cmd); err != nil {
			panic(err)
		}
	},
}

func init() {
	asymCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	verifyCmd.Flags().StringVarP(&sign, "sign", "s", "", "Specify the signature file")
}

var (
	sign string
)

func runVerify(cmd *cobra.Command) error {
	in, err := cmd.Flags().GetString("in")
	if err != nil {
		return err
	}
	input, err := utils.ReadFile(in)
	if err != nil {
		return errors.Wrap(err, "read input file failed")
	}
	var dataDgst []byte
	dgst := cmd.Parent().Flag("dgst").Value.String()
	if dgst != "" {
		dataDgst = cdgst.Sum(dgst, input)
	} else {
		dataDgst = input
	}

	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return err
	}
	keyAny, err := utils.KeyFile2PublicKey(key)
	if err != nil {
		return errors.Wrap(err, "load key file failed")
	}

	signHex, err := utils.ReadFile(sign)
	if err != nil {
		return errors.Wrap(err, "read signature file failed")
	}
	signature, err := utils.Hex2Bytes(string(signHex))
	if err != nil {
		return errors.Wrap(err, "hex to bytes failed")
	}

	var (
		verifyOk bool
	)
	switch pub := keyAny.(type) {
	case *rsa.PublicKey:
		asymRsa := asym.NewRsaNoSha256()
		verifyOk = asymRsa.Verify(dataDgst, signature, pub, nil)
	case *sm2.PublicKey:
		asymSm2 := asym.NewSm2WithSm3()
		verifyOk = asymSm2.Verify(dataDgst, signature, pub)
	case *ecdsa.PublicKey:
		asymEcdsa := asym.NewEccNoHash()
		verifyOk = asymEcdsa.Verify(dataDgst, signature, pub, nil)
	}

	if verbose(cmd) {
		utils.Print(os.Stdout, []byte("sign key type: "+fmt.Sprintf("%T", keyAny)+"\n"))
		utils.Print(os.Stdout, []byte("verify data: "+utils.Bytes2Hex(input)+"\n"))
		utils.Print(os.Stdout, []byte("verify dgst: "+utils.Bytes2Hex(dataDgst)+"\n"))
		utils.Print(os.Stdout, []byte("verify signature: "+utils.Bytes2Hex(signature)+"\n"))
	}

	if verifyOk {
		utils.Print(os.Stdout, []byte("verify ok"))
	} else {
		utils.Print(os.Stdout, []byte("verify failed"))
	}

	return nil
}

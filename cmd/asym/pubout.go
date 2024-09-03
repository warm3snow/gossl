/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package asym

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"github.com/warm3snow/gossl/utils"
	"os"
)

// puboutCmd represents the pubout command
var puboutCmd = &cobra.Command{
	Use:   "pubout",
	Short: "output the public key",
	Long:  `output the public key from the private key file.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runPubOut(cmd); err != nil {
			panic(err)
		}
	},
}

func init() {
	asymCmd.AddCommand(puboutCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// puboutCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// puboutCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runPubOut(cmd *cobra.Command) error {
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return errors.Wrap(err, "get key flag failed")
	}
	keyAny, err := utils.KeyFile2PrivateKey(key)
	if err != nil {
		return errors.Wrap(err, "load key file failed")
	}
	out, _ := cmd.Parent().Flags().GetString("out")

	var (
		pubKey interface{}
	)

	switch asymKey := keyAny.(type) {
	case *rsa.PrivateKey:
		pubKey = asymKey.Public()
	case *sm2.PrivateKey:
		pubKey = asymKey.Public()
	case *ecdsa.PrivateKey:
		pubKey = asymKey.Public()
	default:
		return errors.New("unsupported key type")
	}

	pkBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return errors.Wrap(err, "marshal public key failed")
	}

	pkPem := utils.PublicKey2Pem(pkBytes)
	if out != "" {
		err = utils.WriteFile(out, pkPem)
		if err != nil {
			return errors.Wrap(err, "write public key file failed")
		}
	} else {
		err = utils.Print(os.Stdout, pkPem)
		if err != nil {
			return errors.Wrap(err, "print public key failed")
		}
	}

	return nil
}

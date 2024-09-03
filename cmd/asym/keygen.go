// Package asym /*
package asym

import (
	"crypto/elliptic"
	"crypto/x509"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gmsm/sm2"
	wmx509 "github.com/warm3snow/gmsm/x509"
	"github.com/warm3snow/gossl/crypto"
	"github.com/warm3snow/gossl/crypto/asym"
	"github.com/warm3snow/gossl/utils"
	"os"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "generate a random key",
	Long:  `generate a random asym private key with specified length.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := checkRequiredFlags(cmd, args); err != nil {
			panic(err)
		}

		if err := runKeyGen(); err != nil {
			panic(err)
		}
	},
}

func init() {
	asymCmd.AddCommand(keygenCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// keygenCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keygenCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	// only for rsa
	keygenCmd.Flags().IntVarP(&keyBitLen, "keybitlen", "b", 2048, "Specify the rsa key bit length [2048, 4096]")

	// only for ecdsa
	keygenCmd.Flags().StringVarP(&curve, "curve", "c", "P-256", "Specify the ecc curve [P-256, P-384, P-521]")
}

var (
	algo      string
	out       string
	keyBitLen int
	dgst      string
	curve     string
)

func checkRequiredFlags(cmd *cobra.Command, args []string) error {
	var err error

	algo, err = cmd.Parent().Flags().GetString("algo")
	if err != nil {
		return errors.Wrapf(err, "get flag algo failed")
	}

	out, _ = cmd.Parent().Flags().GetString("out")

	return nil
}

func runKeyGen() error {
	value, exist := crypto.AlgorithmKeyGenMap[algo]
	if !exist {
		return errors.Errorf("unsupported algorithm: %s", algo)
	}

	keyGen := value.(*asym.KeyGen)

	var (
		output []byte
		err    error
	)

	switch algo {
	case "rsa":
		rsaKey, err := keyGen.RSAKeyGen(keyBitLen)
		if err != nil {
			return errors.Wrapf(err, "generate rsa key failed")
		}
		output, err = x509.MarshalPKCS8PrivateKey(rsaKey)
	case "ecdsa":
		ecdsaKey, err := keyGen.ECDSAKeyGen(curveToNamedCurve(curve))
		if err != nil {
			return errors.Wrapf(err, "generate ecdsa key failed")
		}
		output, err = x509.MarshalPKCS8PrivateKey(ecdsaKey)
		if err != nil {
			return errors.Wrapf(err, "marshal ecdsa key failed")
		}
	case "sm2":
		sm2Key, err := keyGen.SM2KeyGen()
		if err != nil {
			return errors.Wrapf(err, "generate sm2 key failed")
		}
		output, err = wmx509.MarshalSm2PrivateKey(sm2Key, nil)
		if err != nil {
			return errors.Wrapf(err, "marshal sm2 key failed")
		}
	}

	keyPem := utils.PKey2Pem(output)
	if out == "" {
		err = utils.Print(keyPem, os.Stdout)
		if err != nil {
			return errors.Wrapf(err, "print key failed")
		}
	} else {
		err = utils.WriteFile(out, keyPem)
		if err != nil {
			return errors.Wrapf(err, "write key to file failed")
		}
	}
	return nil
}

func curveToNamedCurve(curve string) elliptic.Curve {
	switch curve {
	case "SM2":
		return sm2.P256Sm2()
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		panic("unsupported curve")
	}
}

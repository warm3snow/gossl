package asym

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/warm3snow/gossl/crypto/asym"
	cdgst "github.com/warm3snow/gossl/crypto/dgst"
	"github.com/warm3snow/gossl/utils"
	"os"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "asymmetric sign",
	Long:  `asymmetric sign data with specified algorithm and key.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runSign(cmd); err != nil {
			panic(err)
		}
	},
}

func init() {
	asymCmd.AddCommand(signCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// signCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// signCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runSign(cmd *cobra.Command) error {
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return errors.Wrap(err, "get key flag failed")
	}
	keyAny, err := utils.KeyFile2PrivateKey(key)
	if err != nil {
		return errors.Wrap(err, "load key file failed")
	}

	in, err := cmd.Parent().Flags().GetString("in")
	if err != nil {
		return errors.Wrapf(err, "get flag in failed")
	}
	input, err := utils.ReadFile(in)
	if err != nil {
		return errors.Wrap(err, "read input file failed")
	}

	var (
		datadgst  []byte
		signature []byte
	)
	dgst, _ := cmd.Parent().Flags().GetString("dgst")
	if dgst != "" {
		datadgst = cdgst.Sum(dgst, input)
	} else {
		datadgst = input
	}

	out, _ := cmd.Parent().Flags().GetString("out")

	switch priv := keyAny.(type) {
	case *rsa.PrivateKey:
		asymRsa := asym.NewRsaNoSha256()
		signature, err = asymRsa.Sign(datadgst, priv, nil)
	case *sm2.PrivateKey:
		asymSm2 := asym.NewSm2WithSm3()
		signature, err = asymSm2.Sign(datadgst, priv)
	case *ecdsa.PrivateKey:
		asymEcdsa := asym.NewEccNoHash()
		signature, err = asymEcdsa.Sign(datadgst, priv, nil)
	default:
		err = errors.New("unsupported key type")
	}
	if err == nil {
		signHex := utils.Bytes2Hex(signature)
		if out != "" {
			err = utils.WriteFile(out, []byte(signHex))
		} else {
			err = utils.Print(os.Stdout, []byte(signHex))
		}
	}

	if verbose(cmd) {
		utils.Print(os.Stdout, []byte("sign data: "+utils.Bytes2Hex(input)+"\n"))
		utils.Print(os.Stdout, []byte("sign dgst: "+utils.Bytes2Hex(datadgst)+"\n"))
		utils.Print(os.Stdout, []byte("sign signature: "+utils.Bytes2Hex(signature)+"\n"))
	}

	return err
}

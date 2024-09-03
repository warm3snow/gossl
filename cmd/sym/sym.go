package sym

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto"
	"github.com/warm3snow/gossl/crypto/sym"
	"github.com/warm3snow/gossl/utils"
)

// symCmd represents the sym command
var symCmd = &cobra.Command{
	Use:   "sym",
	Short: "encrypt or decrypt file",
	Long:  `encrypt or decrypt file with specified algorithm and key.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := checkRequiredFlags(cmd, args); err != nil {
			panic(err)
		}
		if err := runEnc(); err != nil {
			panic(err)
		}
	},
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// symCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// symCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	symCmd.Flags().StringVarP(&k, "key", "k", "", "Specify the key, hex string")

	symCmd.Flags().BoolVarP(&d, "decrypt", "d", false, "Decrypt the input data")

	symCmd.Flags().BoolVarP(&e, "encrypt", "e", false, "Encrypt the input data")

}

var (
	in   string
	out  string
	algo string
	k    string
	d    bool
	e    bool
)

var (
	input []byte
	key   []byte
)

func SymCmd() *cobra.Command {
	return symCmd
}

func checkRequiredFlags(cmd *cobra.Command, args []string) error {
	var err error
	in, err = cmd.Parent().Flags().GetString("in")
	if err != nil {
		return errors.Wrapf(err, "get flag in failed")
	} else {
		// read file
		input, err = utils.ReadFile(in)
		if err != nil {
			return errors.Wrap(err, "read input file failed")
		}
	}
	if k == "" {
		return errors.New("missing required flag: key")
	} else {
		key, err = utils.Hex2Bytes(k)
		if err != nil {
			return errors.Wrap(err, "parse key failed, not a valid hex string")
		}
	}

	algo, err = cmd.Parent().Flags().GetString("algo")
	if err != nil {
		return errors.Wrapf(err, "get flag algo failed")
	}

	out, err = cmd.Parent().Flags().GetString("out")
	if err != nil {
		return errors.Wrapf(err, "get flag out failed")
	}

	return nil
}

func runEnc() error {
	value, exist := crypto.AlgorithmMap[algo]
	if !exist {
		return errors.Errorf("unsupported algorithm: %s", algo)
	}

	var (
		output []byte
		err    error
	)
	switch value.(type) {
	case *sym.Sm4Cbc:
		sm4Cbc := value.(*sym.Sm4Cbc)
		if d {
			output, err = sm4Cbc.Decrypt(key, input)
		} else {
			output, err = sm4Cbc.Encrypt(key, input)
		}
	case *sym.Aes256Cbc:
		aes256Cbc := value.(*sym.Aes256Cbc)
		if d {
			output, err = aes256Cbc.Decrypt(key, input)
		} else {
			output, err = aes256Cbc.Encrypt(key, input)
		}
	}
	if err != nil {
		return err
	}
	return utils.WriteFile(out, output)
}

package cipher

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto"
	"github.com/warm3snow/gossl/crypto/sym"
	"github.com/warm3snow/gossl/utils"
)

// encCmd represents the enc command
var encCmd = &cobra.Command{
	Use:   "enc",
	Short: "encrypt or decrypt file",
	Long:  `encrypt or decrypt file with specified algorithm and key.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := checkRequiredFlags(); err != nil {
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
	// encCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// encCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	encCmd.Flags().StringVarP(&in, "in", "i", "", "The input file")

	encCmd.Flags().StringVarP(&out, "out", "o", "", "The output file")

	encCmd.Flags().StringVarP(&algo, "algo", "a", "aes-256-cbc", "Specify the supported algorithm")

	encCmd.Flags().StringVarP(&k, "key", "k", "", "Specify the key, hex string")

	encCmd.Flags().BoolVarP(&d, "decrypt", "d", false, "Decrypt the input data")
}

var (
	in   string
	out  string
	algo string
	k    string
	d    bool
)

var (
	input []byte
	key   []byte
)

func EncCmd() *cobra.Command {
	return encCmd
}

func checkRequiredFlags() error {
	var err error
	if in == "" {
		return errors.New("missing required flag: in")
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
	return nil
}

func runEnc() error {
	value, exist := crypto.AlgorithmMap[algo]
	if !exist {
		return errors.New("unsupported algorithm")
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

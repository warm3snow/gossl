package cipher

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto"
	"github.com/warm3snow/gossl/crypto/sym"
	"github.com/warm3snow/gossl/utils"
	"os"
)

// encCmd represents the enc command
var encCmd = &cobra.Command{
	Use:   "enc",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := checkRequiredFlags(); err != nil {
			panic(err)
		}
		run()
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

	in = encCmd.Flags().StringP("in", "i", "", "The input file")

	out = encCmd.Flags().StringP("out", "o", "", "The output file")

	algo = encCmd.Flags().StringP("algo", "a", "aes-256-cbc", "Specify the supported algorithm")

	k = encCmd.Flags().StringP("key", "k", "", "Specify the key, hex string")

	d = encCmd.Flags().BoolP("decrypt", "d", false, "Decrypt the input data")

	iv = encCmd.Flags().String("iv", "", "Specify the iv, hex string")
}

var (
	in   *string
	out  *string
	algo *string
	k    *string
	d    *bool
	iv   *string
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
	if *in == "" {
		return errors.New("missing required flag: in")
	} else {
		// check if file exists
		if _, err := os.Stat(*in); os.IsNotExist(err) {
			return errors.New("input file not exists")
		}
		// read file
		input, err = utils.ReadFile(*in)
		if err != nil {
			return errors.Wrap(err, "read input file failed")
		}
	}
	if *out == "" {
		return errors.New("missing required flag: out")
	} else {
		// check if file exists
		if _, err := os.Stat(*out); os.IsNotExist(err) {
			return errors.New("output file not exists")
		}
	}
	if *k == "" {
		return errors.New("missing required flag: key")
	} else {
		key, err = utils.Hex2Bytes(*k)
		if err != nil {
			return errors.Wrap(err, "parse key failed, not a valid hex string")
		}
	}
	return nil
}

func run() error {
	value, exist := crypto.AlgorithmMap[*algo]
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
		if *d {
			output, err = sm4Cbc.Decrypt([]byte(*k), []byte(*iv), input)
		} else {
			output, err = sm4Cbc.Encrypt([]byte(*k), []byte(*iv), input)
		}
	case *sym.Aes256Cbc:
		aes256Cbc := value.(*sym.Aes256Cbc)
		if *d {
			output, err = aes256Cbc.Decrypt([]byte(*k), []byte(*iv), input)
		} else {
			output, err = aes256Cbc.Encrypt([]byte(*k), []byte(*iv), input)
		}
	}
	if err != nil {
		return err
	}
	return utils.WriteFile(*out, output)
}

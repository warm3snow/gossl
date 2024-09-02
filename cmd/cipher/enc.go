package cipher

import (
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto"
	"github.com/warm3snow/gossl/crypto/sym"
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
		runCipher(cmd, args)
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

	iv = encCmd.Flags().StringP("iv", "v", "", "Specify the iv, hex string")
}

var (
	in   *string
	out  *string
	algo *string
	k    *string
	d    *bool
	iv   *string
)

func EncCmd() *cobra.Command {
	return encCmd
}

func checkRequiredFlags() {
	if *in == "" {
		panic("missing required flag: in")
	}
	if *out == "" {
		panic("missing required flag: out")
	}
	if *k == "" {
		panic("missing required flag: key")
	}
}

func runCipher(cmd *cobra.Command, args []string) {
	value, exist := crypto.AlgorithmMap[*algo]
	if !exist {
		panic("unsupported algorithm")
	}

	switch value.(type) {
	case *sym.Sm4Cbc:
		sm4Cbc := value.(*sym.Sm4Cbc)
		if *d {
			sm4Cbc.Decrypt([]byte(*k), []byte(*iv), nil)
		} else {
			sm4Cbc.Encrypt([]byte(*k), []byte(*iv), nil)
		}
	}
}

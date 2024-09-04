package encode

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto/x509"
	"github.com/warm3snow/gossl/utils"
	"os"
)

// x509Cmd represents the encode command
var x509Cmd = &cobra.Command{
	Use:   "x509",
	Short: "x509 certificate",
	Long:  `x509 certificate - create, parse etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runX509(cmd); err != nil {
			panic(err)
		}
	},
}

func X509Cmd() *cobra.Command {
	return x509Cmd
}

func init() {
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// x509Cmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// x509Cmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runX509(cmd *cobra.Command) error {
	in, err := cmd.Parent().Flags().GetString("in")
	if err != nil {
		return errors.Wrap(err, "failed to get input file")
	}
	input, err := utils.ReadFile(in)
	if err != nil {
		return errors.Wrap(err, "failed to read input file")
	}

	output, err := x509.NewX509Cert().ParseCertToText(string(input))
	if err != nil {
		return errors.Wrap(err, "failed to parse")
	}

	out := cmd.Parent().Flags().Lookup("out").Value.String()
	if out != "" {
		if err := utils.WriteFile(out, output); err != nil {
			return errors.Wrap(err, "failed to write output file")
		}
	} else {
		utils.Print(os.Stdout, output)
	}

	return nil
}

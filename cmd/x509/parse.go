/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package x509

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	_const "github.com/warm3snow/gossl/crypto/const"
	"github.com/warm3snow/gossl/crypto/x509"
	"github.com/warm3snow/gossl/utils"
	"os"
)

// parseCmd represents the parse command
var parseCmd = &cobra.Command{
	Use:   "parse",
	Short: "parse certificate, csr etc.",
	Long:  `parse certificate, csr etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runParse(cmd); err != nil {
			panic(err)
		}
	},
}

func init() {
	x509Cmd.AddCommand(parseCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// parseCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// parseCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runParse(cmd *cobra.Command) error {
	in, err := cmd.Parent().Flags().GetString("in")
	if err != nil {
		return errors.Wrap(err, "failed to get input file")
	}
	input, err := utils.ReadFile(in)
	if err != nil {
		return errors.Wrap(err, "failed to read input file")
	}

	algo := cmd.Parent().Flags().Lookup("algo").Value.String()

	var (
		output []byte
	)
	switch algo {
	case _const.X509.String():
		output, err = x509.NewX509Cert().ParseCertToText(string(input))
	case _const.CSR.String():
		output, err = x509.NewCSR().ParseCsrToText(string(input))
	}

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

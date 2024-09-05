/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package encode

import (
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/x509"
	"github.com/warm3snow/gossl/utils"
	"os"

	"github.com/spf13/cobra"
)

// reqCmd represents the req command
var reqCmd = &cobra.Command{
	Use:   "req",
	Short: "certificate request",
	Long:  `certificate request - create, parse etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runReq(cmd); err != nil {
			panic(err)
		}
	},
}

func ReqCmd() *cobra.Command {
	return reqCmd
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// reqCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// reqCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runReq(cmd *cobra.Command) error {
	in, err := cmd.Parent().Flags().GetString("in")
	if err != nil {
		return errors.Wrap(err, "failed to get input file")
	}
	input, err := utils.ReadFile(in)
	if err != nil {
		return errors.Wrap(err, "failed to read input file")
	}

	output, err := x509.NewCSR().ParseCsrToText(string(input))

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

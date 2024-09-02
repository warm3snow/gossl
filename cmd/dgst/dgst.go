/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package dgst

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/warm3snow/gossl/crypto"
	"github.com/warm3snow/gossl/crypto/dgst"
	"github.com/warm3snow/gossl/utils"

	"github.com/spf13/cobra"
)

// dgstCmd represents the dgst command
var dgstCmd = &cobra.Command{
	Use:   "dgst",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := checkRequiredFlags(cmd, args); err != nil {
			panic(err)
		}
		if err := runDgst(); err != nil {
			panic(err)
		}
	},
}

func DgstCmd() *cobra.Command {
	return dgstCmd
}

func init() {
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dgstCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dgstCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	dgstCmd.Flags().StringVarP(&k, "key", "k", "", "Specify the key, hex string")

}

var (
	in   string
	out  string
	algo string
	k    string
)

var (
	input []byte
	key   []byte
)

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
	if k != "" {
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
	_ = err
	//if err != nil {
	//	return errors.Wrapf(err, "get flag out failed")
	//}

	return nil
}

func runDgst() error {
	value, exist := crypto.AlgorithmMap[algo]
	if !exist {
		return errors.Errorf("unsupported algorithm: %s", algo)
	}

	var (
		output []byte
	)
	switch value.(type) {
	case *dgst.Sha256:
		output = value.(*dgst.Sha256).Sum(input)
	case *dgst.Sm3:
		output = value.(*dgst.Sm3).Sum(input)
	}

	if out != "" {
		if err := utils.WriteFile(out, output); err != nil {
			return errors.Wrap(err, "write output file failed")
		}
	} else {
		fmt.Println(utils.Bytes2Hex(output))
	}
	return nil
}

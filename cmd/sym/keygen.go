/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package sym

import (
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto/sym"
	"github.com/warm3snow/gossl/utils"
	"os"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "generate a random key",
	Long:  `generate a random key with specified length.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runKeyGen(); err != nil {
			panic(err)
		}
	},
}

func init() {
	symCmd.AddCommand(keygenCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// keygenCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keygenCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	len = keygenCmd.Flags().IntP("len", "l", 16, "Specify the key length [16, 24, 32]")
}

var (
	len *int
)

func runKeyGen() error {
	keyBytes, err := sym.NewKeyGen().GenKey(*len)
	if err != nil {
		return err
	}
	keyHex := utils.Bytes2Hex(keyBytes)
	err = utils.Print([]byte(keyHex), os.Stdout)
	if err != nil {
		return err
	}
	return nil
}

/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package kdf

import (
	"github.com/spf13/cobra"
)

// kdfCmd represents the kdf command
var kdfCmd = &cobra.Command{
	Use:   "kdf",
	Short: "key derivation function",
	Long:  `key derivation function is a function that derives a secret key from a secret password.`,
	//Run: func(cmd *cobra.Command, args []string) {
	//	fmt.Println("kdf called")
	//},
}

func KdfCmd() *cobra.Command {
	return kdfCmd
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// kdfCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// kdfCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	kdfCmd.PersistentFlags().StringP("password", "p", "123456",
		"Specify the password used to derive the key")
}

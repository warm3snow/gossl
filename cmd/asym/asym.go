/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package asym

import (
	"github.com/spf13/cobra"
)

// asymCmd represents the asym command
var asymCmd = &cobra.Command{
	Use:   "asym",
	Short: "asymmetric cryptography",
	Long:  `asymmetric cryptography to KeyGen, Sign, Verify, Encrypt, Decrypt, etc.`,
	//Run: func(cmd *cobra.Command, args []string) {
	//	fmt.Println("asym called")
	//},
}

func AsymCmd() *cobra.Command {
	return asymCmd
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// asymCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// asymCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	// only for ras and ecdsa
	keygenCmd.Flags().StringVarP(&dgst, "dgst", "d", "sha256", "Specify the digest algorithm [sha256, sha384, sha512]")
}

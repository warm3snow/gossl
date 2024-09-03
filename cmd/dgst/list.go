/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package dgst

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list supported digest algorithms",
	Long:  `list supported digest algorithms`,
	Run: func(cmd *cobra.Command, args []string) {
		listCiphers()
	},
}

func init() {
	dgstCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func listCiphers() {
	fmt.Println("Supported digest algorithms:")
	for _, algo := range crypto.AlgorithmKindMap["digest"] {
		fmt.Println(algo.(crypto.CryptoAlgorithm).Algorithm())
	}
}

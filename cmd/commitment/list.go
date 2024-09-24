/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package commitment

import (
	"fmt"
	"github.com/warm3snow/gossl/crypto"
	_const "github.com/warm3snow/gossl/crypto/const"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		listCipers()
	},
}

func init() {
	commitmentCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func listCipers() {
	fmt.Println("Supported commitment algorithm list:")
	for _, algo := range crypto.AlgorithmKindMap[_const.CommitmentKind.String()] {
		fmt.Println(algo.(crypto.CryptoAlgorithm).Algorithm())
	}
}

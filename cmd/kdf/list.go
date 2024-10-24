package kdf

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto"
	"github.com/warm3snow/gossl/kdf"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list supported key derivation functions",
	Long:  `list supported key derivation functions`,
	Run: func(cmd *cobra.Command, args []string) {
		listCiphers()
	},
}

func init() {
	kdfCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func listCiphers() {
	fmt.Println("Supported kdf algorithm list:")
	for _, algo := range kdf.AlgorithmKindMap["kdf"] {
		fmt.Println(algo.(crypto.CryptoAlgorithm).Algorithm())
	}
}

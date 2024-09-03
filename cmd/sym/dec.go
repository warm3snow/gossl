/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package sym

import (
	"github.com/spf13/cobra"
)

// decCmd represents the dec command
var decCmd = &cobra.Command{
	Use:   "dec",
	Short: "Symmetric decryption",
	Long:  `Symmetric decryption with specified algorithm and key.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := checkRequiredFlags(cmd, args); err != nil {
			panic(err)
		}
		if err := runEnc(true); err != nil {
			panic(err)
		}
	},
}

func init() {
	symCmd.AddCommand(decCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// decCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// decCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

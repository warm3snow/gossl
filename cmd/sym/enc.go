/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package sym

import (
	"github.com/spf13/cobra"
)

// encCmd represents the enc command
var encCmd = &cobra.Command{
	Use:   "enc",
	Short: "Symmetric encryption",
	Long:  `Symmetric encryption with specified algorithm and key.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := checkRequiredFlags(cmd, args); err != nil {
			panic(err)
		}
		if err := runEnc(false); err != nil {
			panic(err)
		}
	},
}

func init() {
	symCmd.AddCommand(encCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// encCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// encCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

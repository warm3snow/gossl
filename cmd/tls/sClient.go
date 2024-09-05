/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package tls

import (
	"fmt"

	"github.com/spf13/cobra"
)

// sClientCmd represents the sClient command
var sClientCmd = &cobra.Command{
	Use:   "s_client",
	Short: "tls client",
	Long:  `tls client for test and debug`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("sClient called")
	},
}

func init() {
	tlsCmd.AddCommand(sClientCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sClientCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sClientCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

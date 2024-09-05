/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package tls

import (
	"fmt"

	"github.com/spf13/cobra"
)

// tlsCmd represents the tls command
var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "transport layer security(ssl/tls)",
	Long:  `transport layer security(ssl/tls) for test and debug`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("tls called")
	},
}

func TLSCommand() *cobra.Command {
	return tlsCmd
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// tlsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// tlsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

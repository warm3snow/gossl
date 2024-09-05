/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package tls

import (
	"fmt"

	"github.com/spf13/cobra"
)

// sServerCmd represents the sServer command
var sServerCmd = &cobra.Command{
	Use:   "s_server",
	Short: "tls server",
	Long:  `tls server for test and debug`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("sServer called")
	},
}

func init() {
	tlsCmd.AddCommand(sServerCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sServerCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sServerCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package commitment

import (
	"github.com/spf13/cobra"
)

// commitmentCmd represents the commitment command
var commitmentCmd = &cobra.Command{
	Use:   "commitment",
	Short: "cryptographic commitment",
	Long: `cryptographic commitment is a cryptographic primitive that allows one 
to commit to a chosen value (or chosen statement)while keeping it hidden to others, 
with the ability to reveal the committed value later.`,
	//Run: func(cmd *cobra.Command, args []string) {
	//	fmt.Println("commitment called")
	//},
}

func CommitmentCmd() *cobra.Command {
	return commitmentCmd
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// commitmentCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// commitmentCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	commitmentCmd.PersistentFlags().String("in-text", "", "input text to be commitment")
}

package x509

import (
	"github.com/spf13/cobra"
)

// x509Cmd represents the x509 command
var x509Cmd = &cobra.Command{
	Use:   "x509",
	Short: "certificate and certificate request operations",
	Long:  `x509 certificate and certificate request operations - create, parse etc.`,
	//Run: func(cmd *cobra.Command, args []string) {
	//},
}

func X509Cmd() *cobra.Command {
	return x509Cmd
}

func init() {
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// x509Cmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// x509Cmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

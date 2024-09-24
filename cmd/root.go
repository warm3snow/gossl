/*
Copyright © 2024 warm3snow

*/
package cmd

import (
	"fmt"
	"github.com/warm3snow/gossl/cmd/asym"
	"github.com/warm3snow/gossl/cmd/commitment"
	"github.com/warm3snow/gossl/cmd/dgst"
	"github.com/warm3snow/gossl/cmd/encode"
	"github.com/warm3snow/gossl/cmd/kdf"
	"github.com/warm3snow/gossl/cmd/sym"
	"github.com/warm3snow/gossl/cmd/tls"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the sym command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gossl",
	Short: "gossl is a crypto command-line tool",
	Long:  `gossl is a crypto command-line tool like openssl.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Add subcommands
	rootCmd.AddCommand(sym.SymCmd())
	rootCmd.AddCommand(dgst.DgstCmd())
	rootCmd.AddCommand(asym.AsymCmd())
	rootCmd.AddCommand(kdf.KdfCmd())
	rootCmd.AddCommand(encode.X509Cmd())
	rootCmd.AddCommand(encode.ReqCmd())
	rootCmd.AddCommand(tls.TLSCommand())
	rootCmd.AddCommand(commitment.CommitmentCmd())

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.gossl.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	// verbose
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	rootCmd.PersistentFlags().StringP("in", "i", "", "The input file")

	rootCmd.PersistentFlags().StringP("out", "o", "", "The output file")

	rootCmd.PersistentFlags().StringP("algo", "a", "", "Specify the supported algorithm")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".gossl" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".gossl")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

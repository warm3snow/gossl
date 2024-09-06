/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package tls

import (
	"fmt"
	"github.com/spf13/cobra"
	cmtls "github.com/warm3snow/gossl/crypto/gmtls"
)

// sServerCmd represents the sServer command
var sServerCmd = &cobra.Command{
	Use:   "s_server",
	Short: "tls server",
	Long:  `tls server for test and debug`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runServer(cmd); err != nil {
			panic(err)
		}
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

	sServerCmd.Flags().IntVar(&accept, "accept", 4433, "server port to accept")
}

var (
	accept int
)

//openssl s_server -accept 4433 -cert rsa.crt -key rsa.key -www

func runServer(cmd *cobra.Command) error {
	cfg, err := tlsConfig(cmd)
	if err != nil {
		return err
	}
	ln, err := cmtls.Listen("tcp", fmt.Sprintf(":%d", accept), cfg)
	defer ln.Close()

	//lis := cmtls.NewListener(ln, cfg)
	//lis.
	//
	//mux := cmtls.NewServeMux()
	//mux.HandleFunc("/", sayHello)
	//
	//err = http.Serve(ln, mux)
}

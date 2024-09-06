/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package tls

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto/gmtls"
	"net"
)

// sClientCmd represents the sClient command
var sClientCmd = &cobra.Command{
	Use:   "s_client",
	Short: "tls client",
	Long:  `tls client for test and debug`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runClient(cmd); err != nil {
			panic(err)
		}
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

	sClientCmd.Flags().StringVarP(&connect, "connect", "c", "", "server address to connect")
}

var (
	connect string
)

func runClient(cmd *cobra.Command) error {
	cfg, err := tlsConfig(cmd)
	if err != nil {
		return err
	}
	conn, err := net.Dial("tcp", connect)
	if err != nil {
		return errors.Wrap(err, "failed to connect server")
	}
	defer conn.Close()

	tlsConn := gmtls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return errors.Wrap(err, "failed to handshake")
	}

	// do something with tlsConn
	return nil
}

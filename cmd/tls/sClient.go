/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package tls

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/crypto/gmtls"
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
	sClientCmd.Flags().BoolVarP(&skipVerify, "skip_verify", "", false, "skip verify")
	sClientCmd.Flags().StringVarP(&serverName, "server_name", "", "", "server name")

	sClientCmd.Flags().MarkHidden("server_name")
}

var (
	connect    string
	skipVerify bool
	serverName string
)

func runClient(cmd *cobra.Command) error {
	cfg, err := tlsConfig(cmd)
	if err != nil {
		return err
	}

	if skipVerify {
		cfg.InsecureSkipVerify = true
	} else {
		cfg.ServerName = serverName
	}

	if connect == "" {
		return errors.New("server address is required")
	}

	conn, err := gmtls.Dial("tcp", connect, cfg)
	if err != nil {
		return errors.Wrap(err, "failed to connect server")
	}
	defer conn.Close()

	if err = conn.Handshake(); err != nil {
		return errors.Wrap(err, "failed to handshake")
	}

	fmt.Printf("Connected to server %s\n", conn.RemoteAddr())

	//// 读取服务器发送的数据
	//buf, err := io.ReadAll(conn)
	//if err != nil {
	//	log.Fatalf("Error reading from server: %v", err)
	//}
	//
	//fmt.Printf("Received from server: %s\n", string(buf))
	//
	//// 发送数据到服务器
	//message := "Hello from TLS client!"
	//_, err = conn.Write([]byte(message))
	//if err != nil {
	//	log.Fatalf("Error sending message: %v", err)
	//}

	// do something with tlsConn
	return nil
}

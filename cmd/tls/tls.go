/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package tls

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/x509"
	"github.com/warm3snow/gossl/crypto/gmtls"
	"github.com/warm3snow/gossl/utils"

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

	tlsCmd.PersistentFlags().String("cert", "", "certificate file")
	tlsCmd.PersistentFlags().String("key", "", "private key file")
	tlsCmd.PersistentFlags().String("ca", "", "ca certificate file")

	tlsCmd.PersistentFlags().String("enc_cert", "", "encrypt certificate file")
	tlsCmd.PersistentFlags().String("enc_key", "", "encrypt private key file")

	tlsCmd.PersistentFlags().String("tls_version", "1.2", "tls version[tls1.1, tls1.2, gmtls1.1]")
}

func tlsConfig(cmd *cobra.Command) (*gmtls.Config, error) {
	var (
		certFile    = cmd.Flag("cert").Value.String()
		keyFile     = cmd.Flag("key").Value.String()
		caFile      = cmd.Flag("ca").Value.String()
		encCertFile = cmd.Flag("enc_cert").Value.String()
		encKeyFile  = cmd.Flag("enc_key").Value.String()
		tlsVersion  = cmd.Flag("tls_version").Value.String()
	)

	fmt.Printf("certFile: %s\n", certFile)
	fmt.Printf("keyFile: %s\n", keyFile)
	fmt.Printf("caFile: %s\n", caFile)
	fmt.Printf("encCertFile: %s\n", encCertFile)
	fmt.Printf("encKeyFile: %s\n", encKeyFile)
	fmt.Printf("tlsVersion: %s\n", tlsVersion)

	var tlsConfig = &gmtls.Config{}

	if certFile != "" && keyFile != "" {
		cert, err := gmtls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load certificate")
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	if encCertFile != "" && encKeyFile != "" {
		encCert, err := gmtls.LoadX509KeyPair(encCertFile, encKeyFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load encrypt certificate")
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, encCert)
	}

	if caFile != "" {
		certPool := x509.NewCertPool()
		cacert, err := utils.ReadFile(caFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read ca certificate")
		}
		certPool.AppendCertsFromPEM(cacert)
	}

	switch tlsVersion {
	case "tls1.1":
		tlsConfig.MinVersion = gmtls.VersionTLS11
		tlsConfig.MaxVersion = gmtls.VersionTLS11
	case "tls1.2":
		tlsConfig.MinVersion = gmtls.VersionTLS12
		tlsConfig.MaxVersion = gmtls.VersionTLS12
	case "tls1.3":
		tlsConfig.MinVersion = gmtls.VersionTLS13
		tlsConfig.MaxVersion = gmtls.VersionTLS13
	case "gmtls1.1":
		tlsConfig.MinVersion = gmtls.VersionGMSSL
		tlsConfig.MaxVersion = gmtls.VersionGMSSL
	}
	return tlsConfig, nil
}

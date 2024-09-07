/**
 * @Author: xueyanghan
 * @File: config.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/7 09:45
 */

package config

import (
	"io/ioutil"

	"github.com/tjfoc/gmsm/x509"
	"github.com/warm3snow/gossl/crypto/gmtls"
)

// GetConfig return a config for tls
func GetConfig(certFile, keyFile, caCertFile string, isServer bool) (*gmtls.Config, error) {
	sigCert, err := gmtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	if isServer {
		return &gmtls.Config{
			Certificates: []gmtls.Certificate{sigCert},
			ClientCAs:    certPool,
		}, nil
	}
	return &gmtls.Config{
		Certificates: []gmtls.Certificate{sigCert},
		RootCAs:      certPool,
	}, nil
}

// GetGMTLSConfig returns a config for GM double cert tls
func GetGMTLSConfig(certFile, keyFile, encCertFile, encKeyFile, caCertFile string, isServer bool) (*gmtls.Config, error) {
	sigCert, err := gmtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	encCert, err := gmtls.LoadX509KeyPair(encCertFile, encKeyFile)
	if err != nil {
		return nil, err
	}

	// 信任的根证书
	certPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(caCert)

	if isServer {
		return &gmtls.Config{
			Certificates: []gmtls.Certificate{sigCert, encCert},
			ClientCAs:    certPool,
		}, nil
	}
	return &gmtls.Config{
		Certificates: []gmtls.Certificate{sigCert, encCert},
		RootCAs:      certPool,
	}, nil
}

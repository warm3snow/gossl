/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"github.com/tjfoc/gmsm/x509"
	cmtls "github.com/warm3snow/gossl/crypto/gmtls"
	"io/ioutil"
	"net"
	"net/http"
)

//NewTLSListener returns a listener with tls.Config, which support gmtls and tls
func NewTLSListener(inner net.Listener, config *cmtls.Config) net.Listener {
	return cmtls.NewListener(inner, config)
}

//ListenAndServeTLS only supprot gmtls single cert mode. For gmtls, use NewTLSListener
func ListenAndServeTLS(addr, certFile, keyFile, caCertFile string, handler http.Handler) error {
	cfg, err := GetConfig(certFile, keyFile, caCertFile, true)
	if err != nil {
		return err
	}
	ln, err := cmtls.Listen("tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer ln.Close()
	return http.Serve(ln, handler)
}

// GetConfig return a config for tls
func GetConfig(certFile, keyFile, caCertFile string, isServer bool) (*cmtls.Config, error) {
	sigCert, err := cmtls.LoadX509KeyPair(certFile, keyFile)
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
		return &cmtls.Config{
			Certificates: []cmtls.Certificate{sigCert},
			ClientCAs:    certPool,
		}, nil
	}
	return &cmtls.Config{
		Certificates: []cmtls.Certificate{sigCert},
		RootCAs:      certPool,
	}, nil
}

func GetGMTLSConfig(certFile, keyFile, encCertFile, encKeyFile, caCertFile string, isServer bool) (*cmtls.Config, error) {
	sigCert, err := cmtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	encCert, err := cmtls.LoadX509KeyPair(encCertFile, encKeyFile)
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
		return &cmtls.Config{
			GMSupport:    cmtls.NewGMSupport(),
			Certificates: []cmtls.Certificate{sigCert, encCert},
			ClientCAs:    certPool,
		}, nil
	}
	return &cmtls.Config{
		GMSupport:    cmtls.NewGMSupport(),
		Certificates: []cmtls.Certificate{sigCert, encCert},
		RootCAs:      certPool,
	}, nil
}

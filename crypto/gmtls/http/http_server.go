package http

import (
	"github.com/warm3snow/gossl/crypto/gmtls"
	"github.com/warm3snow/gossl/crypto/gmtls/config"
	"net"
	"net/http"
)

//NewTLSListener returns a listener with gmtls.Config, which support gmtls and tls
func NewTLSListener(inner net.Listener, config *gmtls.Config) net.Listener {
	return gmtls.NewListener(inner, config)
}

//ListenAndServeTLS only supprot gmtls single cert mode. For gmtls, use NewTLSListener
func ListenAndServeTLS(addr, certFile, keyFile, caCertFile string, handler http.Handler) error {
	cfg, err := config.GetConfig(certFile, keyFile, caCertFile, true)
	if err != nil {
		return err
	}
	ln, err := gmtls.Listen("tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer ln.Close()
	return http.Serve(ln, handler)
}

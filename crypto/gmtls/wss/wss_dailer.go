package http

import (
	"context"
	tls "github.com/warm3snow/gossl/crypto/gmtls"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

func NewDial(config *tls.Config) *websocket.Dialer {
	if config == nil {
		panic("config must not be nil")
	}
	return &websocket.Dialer{
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			conn, err := tls.DialWithDialer(dialer, network, addr, config)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
		ReadBufferSize:   10,
		WriteBufferSize:  10,
		HandshakeTimeout: 45 * time.Second,
		Proxy:            http.ProxyFromEnvironment,
	}
}

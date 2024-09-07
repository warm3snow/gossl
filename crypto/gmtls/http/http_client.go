package http

import (
	"context"
	tls "github.com/warm3snow/gossl/crypto/gmtls"
	"net"
	"net/http"
	"time"
)

func NewClient(config *tls.Config) *http.Client {
	if config == nil {
		panic("config must not be nil")
	}
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{}
				conn, err := tls.DialWithDialer(dialer, network, addr, config)
				if err != nil {
					return nil, err
				}

				return conn, nil
			},
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			TLSHandshakeTimeout:   10 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

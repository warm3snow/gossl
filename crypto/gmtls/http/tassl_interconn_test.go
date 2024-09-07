package http

import (
	"context"
	"fmt"
	"github.com/warm3snow/gossl/crypto/gmtls/config"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/warm3snow/gossl/crypto/gmtls/gmcredentials"
	"github.com/warm3snow/gossl/crypto/gmtls/gmcredentials/helloworld"

	tls "github.com/warm3snow/gossl/crypto/gmtls"
)

const (
	requestMsg  = "hello, I'm client"
	responseMsg = "hi, I'm server"
)

type server struct{}

func (s *server) SayHello(ctx context.Context, req *helloworld.HelloRequest) (*helloworld.HelloReply, error) {
	log.Printf("Received %s", req.Name)
	return &helloworld.HelloReply{Message: responseMsg}, nil
}

//grpc server
func testGrpcServerRun_GM(t *testing.T) {
	cfg, err := config.GetGMTLSConfig(ssCert, ssKey, seCert, seKey, caCert, true)
	assert.NoError(t, err)
	cfg.ClientAuth = tls.RequireAndVerifyClientCert

	lis, err := net.Listen("tcp", ":44331")
	require.NoError(t, err)

	creds := gmcredentials.NewTLS(cfg)

	s := grpc.NewServer(grpc.Creds(creds))
	helloworld.RegisterGreeterServer(s, &server{})
	err = s.Serve(lis)

	require.NoError(t, err)
}

func testGrpcClientRun_GM(t *testing.T, finish chan bool) {
	cfg, err := config.GetGMTLSConfig(ssCert, ssKey, seCert, seKey, caCert, false)
	assert.NoError(t, err)
	cfg.CipherSuites = []uint16{tls.GMTLS_ECC_SM4_CBC_SM3}
	cfg.ServerName = "chainmaker.org"
	cfg.InsecureSkipVerify = false

	creds := gmcredentials.NewTLS(cfg)
	conn, err := grpc.Dial("localhost:44331", grpc.WithTransportCredentials(creds))
	defer conn.Close()
	require.NoError(t, err)

	c := helloworld.NewGreeterClient(conn)
	r, err := c.SayHello(context.Background(), &helloworld.HelloRequest{Name: requestMsg})
	require.NoError(t, err)
	require.Equal(t, responseMsg, r.Message)

	finish <- true
}

func testHttpsServerRun_GM(t *testing.T) {
	cfg, err := config.GetGMTLSConfig(ssCert, ssKey, seCert, seKey, caCert, true)
	assert.NoError(t, err)
	cfg.ClientAuth = tls.RequireAndVerifyClientCert

	ln, err := tls.Listen("tcp", ":44330", cfg)
	assert.NoError(t, err)
	defer ln.Close()

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "hello\n")
	})
	fmt.Println(">> HTTP Over [GMSSL/TLS] running..")
	err = http.Serve(ln, nil)
	if err != nil {
		panic(err)
	}
}

func testHttpsClientRun_GM(t *testing.T, finish chan bool) {
	cfg, err := config.GetGMTLSConfig(ssCert, ssKey, seCert, seKey, caCert, false)
	assert.NoError(t, err)
	cfg.CipherSuites = []uint16{tls.GMTLS_ECC_SM4_CBC_SM3}
	cfg.ServerName = "chainmaker.org"
	cfg.InsecureSkipVerify = false

	conn, err := tls.Dial("tcp", "localhost:44330", cfg)
	assert.NoError(t, err)
	defer conn.Close()

	//this commented code is used to test tassl server
	//for i := 0; i < 10; i++ {
	//	req := []byte(fmt.Sprintf("hello chainmaker%d\n", i))
	//	_, _ = conn.Write(req)
	//
	//	time.Sleep(time.Second * 3)
	//}

	req := []byte("GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	conn.Write(req)

	fmt.Println(">> GMTLS_ECC_SM4_CBC_SM3 suite [PASS]")

	finish <- true
}

func TestGMTLS(t *testing.T) {
	finish := make(chan bool, 2)
	//test grpc gmtls
	go testGrpcServerRun_GM(t)
	time.Sleep(time.Second * 2) //wait for server start
	go testGrpcClientRun_GM(t, finish)

	//test https gmtls
	go testHttpsServerRun_GM(t)
	time.Sleep(time.Second * 2) //wait for server start
	go testHttpsClientRun_GM(t, finish)

	for i := 0; i < len(finish); i++ {
		<-finish
	}
}

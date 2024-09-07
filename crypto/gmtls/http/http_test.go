package http

import (
	"github.com/warm3snow/gossl/crypto/gmtls/config"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	tls "github.com/warm3snow/gossl/crypto/gmtls"
)

var (
	caCert, _ = filepath.Abs("../testdata/certs/CA.crt")

	ssCert, _ = filepath.Abs("../testdata/certs/SS.crt")
	ssKey, _  = filepath.Abs("../testdata/certs/SS.key")
	seCert, _ = filepath.Abs("../testdata/certs/SE.crt")
	seKey, _  = filepath.Abs("../testdata/certs/SE.key")

	csCert, _ = filepath.Abs("../testdata/certs/CS.crt")
	csKey, _  = filepath.Abs("../testdata/certs/CS.key")
	ceCert, _ = filepath.Abs("../testdata/certs/CE.crt")
	ceKey, _  = filepath.Abs("../testdata/certs/CE.key")
)

var (
	msg = []byte("hello world")
)

func sayHello(w http.ResponseWriter, r *http.Request) {
	w.Write(msg)
}

//TestHttpsServer test ecc certificate
func TestHttpsServer(t *testing.T) {
	finish := make(chan bool, 1)
	go func() {
		err := ListenAndServeTLS(
			":13001",
			"../testdata/certs/single/server.crt",
			"../testdata/certs/single/server.key",
			"../testdata/certs/single/ca.crt",
			http.HandlerFunc(sayHello),
		)
		assert.NoError(t, err)
	}()

	{
		finish <- true
		cfg, err := config.GetConfig(
			"../testdata/certs/single/client.crt",
			"../testdata/certs/single/client.key",
			"../testdata/certs/single/ca.crt",
			false,
		)
		assert.NoError(t, err)

		client := NewClient(cfg)
		resp, err := client.Get("https://localhost:13001")
		assert.NoError(t, err)

		buf, err := ioutil.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, msg, buf)
		log.Println("receive from server: " + string(buf))
	}

	<-finish
}

func testHttpsServerRun(t *testing.T, addr string) {
	cfg, err := config.GetConfig(ssCert, ssKey, caCert, true)
	assert.NoError(t, err)
	cfg.ClientAuth = tls.RequireAndVerifyClientCert

	ln, err := tls.Listen("tcp", addr, cfg)
	assert.NoError(t, err)
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", sayHello)

	err = http.Serve(ln, mux)
	assert.NoError(t, err)
}

func testHttpsClientRun(t *testing.T, url string, finish chan bool) {
	cfg, err := config.GetConfig(csCert, csKey, caCert, false)
	assert.NoError(t, err)
	cfg.ServerName = "chainmaker.org"

	client := NewClient(cfg)
	resp, err := client.Get(url)
	assert.NoError(t, err)

	buf, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, msg, buf)
	log.Println("receive from server: " + string(buf))

	finish <- true
}

func testHttpsServerRun_GM1(t *testing.T, addr string) {
	cfg, err := config.GetGMTLSConfig(ssCert, ssKey, seCert, seKey, caCert, true)
	assert.NoError(t, err)
	cfg.ClientAuth = tls.RequireAndVerifyClientCert

	ln, err := tls.Listen("tcp", addr, cfg)
	assert.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", sayHello)

	err = http.Serve(ln, mux)
	assert.NoError(t, err)
}

func testHttpsClientRun_GM1(t *testing.T, url string, finish chan bool) {
	cfg, err := config.GetGMTLSConfig(csCert, csKey, ceCert, ceKey, caCert, false)
	assert.NoError(t, err)
	cfg.ServerName = "chainmaker.org"
	cfg.InsecureSkipVerify = false

	client := NewClient(cfg)
	resp, err := client.Get(url)
	assert.NoError(t, err)

	buf, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, msg, buf)
	log.Println("receive from server: " + string(buf))

	finish <- true
}
func TestGMHttps(t *testing.T) {
	finish := make(chan bool, 2)
	go testHttpsServerRun(t, ":13002")
	time.Sleep(time.Second * 2) //wait for server start
	go testHttpsClientRun(t, "https://localhost:13002", finish)

	go testHttpsServerRun_GM1(t, ":13003")
	time.Sleep(time.Second * 2) //wait for server start
	go testHttpsClientRun_GM1(t, "https://localhost:13003", finish)

	for i := 0; i < len(finish); i++ {
		<-finish
	}
}

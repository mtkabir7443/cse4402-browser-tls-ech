package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This is a real loopback TLS exchange using an explicit trust anchor, not a
// certificate-verification bypass. Browser discovery is tested separately.
func TestECHTrustedLoopbackControls(t *testing.T) {
	dataDir = ".runtime"
	if _, err := os.Stat(filepath.Join(dataDir, "server.pem")); err != nil {
		t.Skip("run tlslab -mode init before integration verification")
	}
	m := loadMaterials()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dataDir, "server.pem"), filepath.Join(dataDir, "server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(dataDir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid trust anchor")
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: m.Current.Config, PrivateKey: m.Current.PrivateKey, SendAsRetry: true}}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	states := make(chan tls.ConnectionState, 8)
	go func() {
		for {
			raw, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn := tls.Server(raw, cfg)
				if conn.Handshake() == nil {
					states <- conn.ConnectionState()
				}
			}()
		}
	}()
	dial := func(ech []byte) (*tls.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{ServerName: "valid.tlslab.test", RootCAs: roots, MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: ech})
	}
	conn, err := dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	if conn.ConnectionState().ECHAccepted {
		t.Fatal("non-ECH control incorrectly accepted ECH")
	}
	conn.Close()
	s := <-states
	if s.ECHAccepted {
		t.Fatal("server baseline marked ECH")
	}
	conn, err = dial(vector(m.Current.Config))
	if err != nil {
		t.Fatal(err)
	}
	if !conn.ConnectionState().ECHAccepted {
		t.Fatal("valid config not accepted by client")
	}
	conn.Close()
	s = <-states
	if !s.ECHAccepted || s.ServerName != "valid.tlslab.test" {
		t.Fatalf("server failed inner-SNI/ECH check: %+v", s)
	}
	_, err = dial(vector(m.Old.Config))
	var rejection *tls.ECHRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("stale config should return authenticated ECH rejection, got %v", err)
	}
	if len(rejection.RetryConfigList) == 0 {
		t.Fatal("no retry configuration")
	}
	s = <-states
	if s.ECHAccepted || s.ServerName != "public.tlslab.test" {
		t.Fatalf("stale outer handshake wrong: %+v", s)
	}
	conn, err = dial(rejection.RetryConfigList)
	if err != nil {
		t.Fatal(err)
	}
	if !conn.ConnectionState().ECHAccepted {
		t.Fatal("retry did not accept ECH")
	}
	conn.Close()
	s = <-states
	if !s.ECHAccepted {
		t.Fatal("server retry not accepted")
	}
}

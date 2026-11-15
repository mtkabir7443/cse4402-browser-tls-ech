package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func auditTestCredentials(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	certPath := filepath.Join(".runtime", "server.pem")
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		t.Skip("run tlslab -mode init before integration verification")
	}
	cert, err := tls.LoadX509KeyPair(certPath, filepath.Join(".runtime", "server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(".runtime", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid lab trust anchor")
	}
	return cert, roots
}

// Observing the underlying Accept makes the idle-first ordering deterministic.
// The close signal also lets cleanup wait for the audit goroutine to finish
// writing before t.Chdir restores the working directory.
type auditObservedConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *auditObservedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type auditObservedListener struct {
	net.Listener
	accepted chan *auditObservedConn
}

func (l *auditObservedListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c := &auditObservedConn{Conn: raw, closed: make(chan struct{})}
	l.accepted <- c
	return c, nil
}

func TestAuditedListenerIdleConnectionDoesNotBlockTLS(t *testing.T) {
	cert, roots := auditTestCredentials(t)
	t.Chdir(t.TempDir())
	if err := os.Mkdir("evidence", 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	observed := &auditObservedListener{Listener: raw, accepted: make(chan *auditObservedConn, 2)}
	listener := newAuditedListener(observed, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, "concurrency-control")
	var idle net.Conn
	var active *tls.Conn
	var delivered net.Conn
	var serverConnections []*auditObservedConn
	t.Cleanup(func() {
		if idle != nil {
			idle.Close()
		}
		if active != nil {
			active.Close()
		}
		if delivered != nil {
			delivered.Close()
		}
		listener.Close()
		for len(observed.accepted) > 0 {
			serverConnections = append(serverConnections, <-observed.accepted)
		}
		for _, c := range serverConnections {
			// Force a blocked handshake to finish even when an assertion failed.
			_ = c.SetDeadline(time.Now())
			select {
			case <-c.closed:
			case <-time.After(3 * time.Second):
				t.Error("owned TLS connection did not finish cleanup")
			}
		}
	})
	idle, err = net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-observed.accepted:
		serverConnections = append(serverConnections, c)
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not accept the initial idle TCP connection")
	}

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- acceptResult{conn, err}
	}()
	started := time.Now()
	active, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", listener.Addr().String(), &tls.Config{
		RootCAs:    roots,
		ServerName: "valid.tlslab.test",
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("trusted TLS handshake was blocked by an idle socket: %v", err)
	}
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("audited Accept failed: %v", result.err)
		}
		delivered = result.conn
		if delivered.RemoteAddr().String() != active.LocalAddr().String() {
			t.Fatal("Accept did not deliver the completed second connection")
		}
	case <-time.After(time.Until(started.Add(3 * time.Second))):
		t.Fatal("completed TLS connection was not delivered within three seconds")
	}
	if state := active.ConnectionState(); !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		t.Fatal("second connection did not complete authenticated TLS")
	}
}

func TestEventLogWriteFailurePropagates(t *testing.T) {
	t.Chdir(t.TempDir())
	// A regular file in place of the evidence directory deterministically makes
	// opening evidence/server-events.jsonl fail, including on Windows.
	if err := os.WriteFile("evidence", []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := event("write-failure-control", map[string]any{"client_ip": "127.0.0.1"}); err == nil {
		t.Fatal("event reported success when the log could not be opened")
	}
}

func TestFixtureCertificateVerificationRejectsInvalidTrust(t *testing.T) {
	cert, roots := auditTestCredentials(t)
	for _, tc := range []struct {
		name       string
		serverName string
		roots      *x509.CertPool
	}{
		{"unknown-authority", "valid.tlslab.test", x509.NewCertPool()},
		{"wrong-hostname", "outside.example", roots},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			finished := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					finished <- err
					return
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
				finished <- conn.Handshake()
			}()
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", listener.Addr().String(), &tls.Config{
				RootCAs: tc.roots, ServerName: tc.serverName, MinVersion: tls.VersionTLS13,
			})
			if conn != nil {
				conn.Close()
			}
			var certificateError *tls.CertificateVerificationError
			if !errors.As(err, &certificateError) {
				t.Errorf("expected certificate verification failure, got %v", err)
			} else if tc.name == "unknown-authority" {
				var unknown x509.UnknownAuthorityError
				if !errors.As(err, &unknown) {
					t.Errorf("expected an unknown CA error, got %v", err)
				}
			} else {
				var hostname x509.HostnameError
				if !errors.As(err, &hostname) {
					t.Errorf("expected a hostname mismatch, got %v", err)
				}
			}
			select {
			case serverErr := <-finished:
				if serverErr == nil {
					t.Error("server completed the rejected client handshake")
				}
			case <-time.After(4 * time.Second):
				t.Error("owned certificate-control server did not finish")
			}
		})
	}
}

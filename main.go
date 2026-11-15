package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var dataDir string
var eventMu sync.Mutex
var sequence atomic.Uint64

type echMaterial struct {
	Config     []byte `json:"config"`
	PrivateKey []byte `json:"private_key"`
}
type materials struct {
	Current echMaterial `json:"current"`
	Old     echMaterial `json:"old"`
}

func u16(n int) []byte       { return []byte{byte(n >> 8), byte(n)} }
func vector(b []byte) []byte { return append(u16(len(b)), b...) }
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func writeJSON(path string, v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	must(e)
	must(os.WriteFile(path, b, 0600))
}
func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	must(e)
	return n
}
func pemWrite(name, typ string, b []byte) {
	must(os.WriteFile(filepath.Join(dataDir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0600))
}
func newECH(id byte) echMaterial {
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	must(e)
	content := []byte{id, 0, 0x20}
	content = append(content, vector(key.PublicKey().Bytes())...)
	content = append(content, 0, 4, 0, 1, 0, 1, 0)
	public := []byte("public.tlslab.test")
	content = append(content, byte(len(public)))
	content = append(content, public...)
	content = append(content, 0, 0)
	cfg := append([]byte{0xfe, 0x0d}, vector(content)...)
	return echMaterial{cfg, key.Bytes()}
}
func setup() {
	must(os.MkdirAll(dataDir, 0700))
	if _, e := os.Stat(filepath.Join(dataDir, "ca.pem")); e == nil {
		log.Fatal("CA exists; reuse existing lab material instead of replacing trust identity")
	}
	caKey, e := rsa.GenerateKey(rand.Reader, 2048)
	must(e)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "CSE4402 isolated TLS lab " + now.UTC().Format("20060102T150405Z")}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 2, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	must(e)
	pemWrite("ca.pem", "CERTIFICATE", caDER)
	pemWrite("ca-key.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey))
	must(os.WriteFile(filepath.Join(dataDir, "ca.cer"), caDER, 0600))
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	must(e)
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "*.tlslab.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 1, 0), DNSNames: []string{"*.tlslab.test", "tlslab.test", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
	must(e)
	pemWrite("server.pem", "CERTIFICATE", der)
	pemWrite("server-key.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	m := materials{newECH(17), newECH(16)}
	writeJSON(filepath.Join(dataDir, "ech-private.json"), m)
	writeJSON(filepath.Join(dataDir, "ech-public.json"), map[string]any{"current_config_list": base64.StdEncoding.EncodeToString(vector(m.Current.Config)), "stale_config_list": base64.StdEncoding.EncodeToString(vector(m.Old.Config)), "public_name": "public.tlslab.test"})
	fmt.Println("Generated local-only CA, server certificate and independent current/stale ECH keys.")
}
func loadMaterials() materials {
	b, e := os.ReadFile(filepath.Join(dataDir, "ech-private.json"))
	must(e)
	var m materials
	must(json.Unmarshal(b, &m))
	return m
}
func event(kind string, fields map[string]any) error {
	fields["event"] = kind
	fields["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	b, e := json.Marshal(fields)
	if e != nil {
		log.Print(e)
		return e
	}
	eventMu.Lock()
	defer eventMu.Unlock()
	f, e := os.OpenFile(filepath.Join("evidence", "server-events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		log.Print(e)
		return e
	}
	defer f.Close()
	_, e = f.Write(append(b, '\n'))
	if e != nil {
		log.Print(e)
	}
	return e
}
func ipOnly(addr string) string {
	h, _, e := net.SplitHostPort(addr)
	if e != nil {
		return addr
	}
	return h
}
func stateFields(s tls.ConnectionState) map[string]any {
	return map[string]any{"tls_version": tls.VersionName(s.Version), "cipher_suite": tls.CipherSuiteName(s.CipherSuite), "ech_accepted": s.ECHAccepted, "server_name": s.ServerName, "resumed": s.DidResume, "alpn": s.NegotiatedProtocol}
}

type auditedListener struct {
	net.Listener
	config  *tls.Config
	fixture string
	ready   chan net.Conn
	errors  chan error
	stop    chan struct{}
	once    sync.Once
}

func newAuditedListener(ln net.Listener, cfg *tls.Config, name string) *auditedListener {
	l := &auditedListener{Listener: ln, config: cfg, fixture: name, ready: make(chan net.Conn), errors: make(chan error, 1), stop: make(chan struct{})}
	go l.pump()
	return l
}
func (l *auditedListener) Close() error {
	var e error
	l.once.Do(func() { close(l.stop); e = l.Listener.Close() })
	return e
}
func (l *auditedListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case e := <-l.errors:
		return nil, e
	case <-l.stop:
		return nil, net.ErrClosed
	}
}
func (l *auditedListener) pump() {
	limit := make(chan struct{}, 64)
	for {
		raw, e := l.Listener.Accept()
		if e != nil {
			select {
			case l.errors <- e:
			case <-l.stop:
			}
			return
		}
		select {
		case limit <- struct{}{}:
		case <-l.stop:
			raw.Close()
			return
		}
		go func(raw net.Conn) {
			defer func() { <-limit }()
			observed := &helloConn{Conn: raw}
			conn := tls.Server(observed, l.config)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			handshakeErr := conn.HandshakeContext(ctx)
			cancel()
			fields := stateFields(conn.ConnectionState())
			for key, value := range observed.hello {
				fields[key] = value
			}
			fields["connection_id"] = sequence.Add(1)
			fields["remote_address"] = raw.RemoteAddr().String()
			fields["client_ip"] = ipOnly(raw.RemoteAddr().String())
			fields["fixture"] = l.fixture
			if handshakeErr != nil {
				fields["success"] = false
				fields["error"] = handshakeErr.Error()
				event("handshake", fields)
				raw.Close()
				return
			}
			fields["success"] = true
			if e := event("handshake", fields); e != nil {
				raw.Close()
				return
			}
			select {
			case l.ready <- conn:
			case <-l.stop:
				raw.Close()
			}
		}(raw)
	}
}
func listen(port int, name string, cfg *tls.Config, h http.Handler) {
	ln, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	must(e)
	server := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Second, ErrorLog: log.New(os.Stderr, name+": ", 0)}
	server.SetKeepAlivesEnabled(false)
	fmt.Printf("%s https://127.0.0.1:%d\n", name, port)
	go func() {
		if e := server.Serve(newAuditedListener(ln, cfg, name)); e != nil && e != http.ErrServerClosed {
			log.Print(e)
		}
	}()
}
func dnsResponse(query []byte, m materials) ([]byte, string, uint16, error) {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, "", 0, fmt.Errorf("one DNS question required")
	}
	off := 12
	labels := []string{}
	for {
		if off >= len(query) {
			return nil, "", 0, io.ErrUnexpectedEOF
		}
		n := int(query[off])
		off++
		if n == 0 {
			break
		}
		if n > 63 || off+n > len(query) {
			return nil, "", 0, fmt.Errorf("invalid DNS label")
		}
		labels = append(labels, string(query[off:off+n]))
		off += n
	}
	if off-12 > 255 {
		return nil, "", 0, fmt.Errorf("DNS name exceeds 255 octets")
	}
	if off+4 > len(query) {
		return nil, "", 0, io.ErrUnexpectedEOF
	}
	typ := binary.BigEndian.Uint16(query[off : off+2])
	if binary.BigEndian.Uint16(query[off+2:off+4]) != 1 || binary.BigEndian.Uint16(query[2:4])&0xf800 != 0 {
		return nil, "", 0, fmt.Errorf("only standard IN queries supported")
	}
	off += 4
	name := strings.ToLower(strings.Join(labels, "."))
	labels = strings.Split(name, ".")
	host := name
	if len(labels) > 2 && strings.HasPrefix(labels[0], "_") && labels[1] == "_https" {
		host = strings.Join(labels[2:], ".")
	}
	ports := map[string]int{"valid": 9443, "stale": 9443, "baseline": 9443, "public": 9443, "tls10": 9440, "tls11": 9441, "tls12": 9442, "tls13": 9443, "tls12-aes128": 9445, "tls12-chacha": 9446, "tls13-aes128": 9451, "tls13-aes256": 9452, "tls13-chacha": 9453}
	port, known := ports[strings.TrimSuffix(host, ".tlslab.test")]
	known = known && strings.HasSuffix(host, ".tlslab.test")
	var body []byte
	if known && typ == 1 {
		body = []byte{127, 0, 0, 1}
	}
	if known && typ == 65 && host != "public.tlslab.test" {
		body = []byte{0, 1} // priority 1, explicit service hostname (not the _port._https owner)
		for _, label := range strings.Split(host, ".") {
			body = append(body, byte(len(label)))
			body = append(body, label...)
		}
		body = append(body, 0)
		param := func(key int, val []byte) { body = append(body, u16(key)...); body = append(body, vector(val)...) }
		param(1, append([]byte{8}, []byte("http/1.1")...))
		param(3, u16(port))
		param(4, []byte{127, 0, 0, 1})
		if strings.HasPrefix(host, "valid.") {
			param(5, vector(m.Current.Config))
		}
		if strings.HasPrefix(host, "stale.") {
			param(5, vector(m.Old.Config))
		}
	}
	reply := make([]byte, 12)
	copy(reply[0:2], query[0:2])
	binary.BigEndian.PutUint16(reply[2:4], 0x8180)
	reply[5] = 1
	reply = append(reply, query[12:off]...)
	if body != nil {
		reply[7] = 1
		reply = append(reply, 0xc0, 0x0c)
		reply = append(reply, u16(int(typ))...)
		reply = append(reply, 0, 1, 0, 0, 0, 30)
		reply = append(reply, vector(body)...)
	}
	return reply, name, typ, nil
}
func probeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "https://127.0.0.1:8443")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	data := stateFields(*r.TLS)
	data["run_id"] = r.URL.Query().Get("run")
	data["host"] = r.Host
	data["client_ip"] = ipOnly(r.RemoteAddr)
	data["remote_address"] = r.RemoteAddr
	data["user_agent"] = r.UserAgent()
	if e := event("http_result", data); e != nil {
		http.Error(w, "result log write failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func serve() {
	m := loadMaterials()
	cert, e := tls.LoadX509KeyPair(filepath.Join(dataDir, "server.pem"), filepath.Join(dataDir, "server-key.pem"))
	must(e)
	must(os.MkdirAll("evidence", 0700))
	base := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		var b []byte
		var e error
		if r.Method == "GET" {
			b, e = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		} else if r.Method == "POST" {
			b, e = io.ReadAll(http.MaxBytesReader(w, r.Body, 65535))
		} else {
			http.Error(w, "method", 405)
			return
		}
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		answer, name, typ, e := dnsResponse(b, m)
		event("dns_query", map[string]any{"name": name, "type": typ, "client_ip": ipOnly(r.RemoteAddr)})
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(answer)
	})
	registerResultsAPI(mux)
	mux.HandleFunc("/api/browsers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, "browsers.json")
	})
	mux.Handle("/", http.FileServer(http.Dir("web")))
	listen(8443, "dashboard-doh", base.Clone(), mux)
	probe := http.HandlerFunc(probeHandler)
	for _, f := range []struct {
		port    int
		name    string
		version uint16
		suite   uint16
	}{{9440, "tls10", tls.VersionTLS10, 0}, {9441, "tls11", tls.VersionTLS11, 0}, {9442, "tls12", tls.VersionTLS12, 0}, {9445, "tls12-aes128", tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, {9446, "tls12-chacha", tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}} {
		cfg := base.Clone()
		cfg.MinVersion = f.version
		cfg.MaxVersion = f.version
		if f.suite != 0 {
			cfg.CipherSuites = []uint16{f.suite}
		}
		listen(f.port, f.name, cfg, probe)
	}
	ech := base.Clone()
	ech.MinVersion = tls.VersionTLS13
	ech.MaxVersion = tls.VersionTLS13
	ech.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{Config: m.Current.Config, PrivateKey: m.Current.PrivateKey, SendAsRetry: true}}
	listen(9443, "tls13-ech", ech, probe)
	event("server_start", map[string]any{"address": "127.0.0.1", "pid": os.Getpid()})
	select {}
}
func directProbe() {
	m := loadMaterials()
	root, e := os.ReadFile(filepath.Join(dataDir, "ca.pem"))
	must(e)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		log.Fatal("invalid CA")
	}
	results := []map[string]any{}
	allPassed := true
	for _, kind := range []string{"baseline", "valid", "stale"} {
		cfg := &tls.Config{RootCAs: roots, ServerName: kind + ".tlslab.test", MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
		if kind == "valid" {
			cfg.EncryptedClientHelloConfigList = vector(m.Current.Config)
		}
		if kind == "stale" {
			cfg.EncryptedClientHelloConfigList = vector(m.Old.Config)
		}
		row := map[string]any{"case": kind, "client": "Go independent fixture probe"}
		dial := net.Dialer{Timeout: 5 * time.Second}
		conn, e := tls.DialWithDialer(&dial, "tcp", "127.0.0.1:9443", cfg)
		if e != nil {
			row["error"] = e.Error()
			if rejection, ok := e.(*tls.ECHRejectionError); ok {
				row["retry_config_length"] = len(rejection.RetryConfigList)
				retry := cfg.Clone()
				retry.EncryptedClientHelloConfigList = rejection.RetryConfigList
				conn, e = tls.DialWithDialer(&dial, "tcp", "127.0.0.1:9443", retry)
				if e == nil {
					row["retry_ech_accepted"] = conn.ConnectionState().ECHAccepted
					conn.Close()
				} else {
					row["retry_error"] = e.Error()
				}
			}
		} else {
			row["ech_accepted"] = conn.ConnectionState().ECHAccepted
			row["tls_version"] = tls.VersionName(conn.ConnectionState().Version)
			conn.Close()
		}
		passed := false
		switch kind {
		case "baseline":
			accepted, ok := row["ech_accepted"].(bool)
			passed = ok && !accepted
		case "valid":
			accepted, ok := row["ech_accepted"].(bool)
			passed = ok && accepted
		case "stale":
			accepted, ok := row["retry_ech_accepted"].(bool)
			n, _ := row["retry_config_length"].(int)
			passed = ok && accepted && n > 0
		}
		row["passed"] = passed
		allPassed = allPassed && passed
		results = append(results, row)
	}
	writeJSON(filepath.Join("evidence", "independent-ech-probe.json"), results)
	b, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(b))
	if !allPassed {
		os.Exit(1)
	}
}
func main() {
	mode := flag.String("mode", "serve", "init, serve or probe")
	flag.StringVar(&dataDir, "data", ".runtime", "private lab state directory")
	flag.Parse()
	switch *mode {
	case "init":
		setup()
	case "serve":
		serve()
	case "probe":
		directProbe()
	default:
		log.Fatal("invalid mode")
	}
}

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"time"
)

// Capture a ClientHello produced by crypto/tls, independently of the observer's
// decoder. The exchange intentionally ends before server authentication; no
// certificate-verification bypass or external connection is used.
func actualClientHello(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	clientWire, capture := net.Pipe()
	_ = clientWire.SetDeadline(time.Now().Add(3 * time.Second))
	_ = capture.SetDeadline(time.Now().Add(3 * time.Second))
	finished := make(chan error, 1)
	go func() {
		client := tls.Client(clientWire, config)
		finished <- client.Handshake()
		client.Close()
	}()
	t.Cleanup(func() {
		capture.Close()
		clientWire.Close()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("owned ClientHello generator did not stop")
		}
	})
	var wire, payload []byte
	for len(wire) < 65536 {
		header := make([]byte, 5)
		if _, err := io.ReadFull(capture, header); err != nil {
			t.Fatal(err)
		}
		if header[0] != 22 {
			t.Fatalf("expected a TLS handshake record, got %d", header[0])
		}
		data := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
		if _, err := io.ReadFull(capture, data); err != nil {
			t.Fatal(err)
		}
		wire = append(wire, header...)
		wire = append(wire, data...)
		payload = append(payload, data...)
		if len(payload) >= 4 {
			size := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
			if payload[0] == 1 && len(payload) >= 4+size {
				return wire
			}
		}
	}
	t.Fatal("generated ClientHello exceeds test capture bound")
	return nil
}

func TestObserveActualPlainAndECHClientHellos(t *testing.T) {
	plain := actualClientHello(t, &tls.Config{ServerName: "valid.tlslab.test", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13})
	observed, complete, err := parseClientHello(plain)
	if err != nil || !complete {
		t.Fatalf("failed to decode generated plain ClientHello: complete=%v err=%v", complete, err)
	}
	if observed["outer_server_name"] != "valid.tlslab.test" || observed["ech_offered"] != false {
		t.Fatalf("incorrect plain ClientHello fields: %+v", observed)
	}
	if !reflect.DeepEqual(observed["offered_version_ids"], []string{"0x0304", "0x0303"}) {
		t.Fatalf("did not recover TLS 1.3/1.2 offer: %+v", observed)
	}
	var cipherFound bool
	for _, suite := range observed["offered_cipher_ids"].([]string) {
		cipherFound = cipherFound || suite == "0x1301"
	}
	if !cipherFound {
		t.Fatal("generated TLS 1.3 ClientHello should offer AES-128-GCM")
	}

	material := newECH(17)
	ech := actualClientHello(t, &tls.Config{ServerName: "valid.tlslab.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		EncryptedClientHelloConfigList: vector(material.Config)})
	observed, complete, err = parseClientHello(ech)
	if err != nil || !complete {
		t.Fatalf("failed to decode generated ECH outer ClientHello: %v", err)
	}
	if observed["outer_server_name"] != "public.tlslab.test" || observed["ech_offered"] != true || observed["ech_config_id"] != 17 {
		t.Fatalf("incorrect ECH outer wire evidence: %+v", observed)
	}
	if _, exists := observed["ech_accepted"]; exists {
		t.Fatal("wire observer must not manufacture an ECH acceptance verdict")
	}
}

func TestClientHelloRecordFragmentationAndPrefixes(t *testing.T) {
	wire := actualClientHello(t, &tls.Config{ServerName: "fragmented.tlslab.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	want, complete, err := parseClientHello(wire)
	if err != nil || !complete {
		t.Fatal("could not decode reference ClientHello")
	}
	var payload []byte
	for off := 0; off < len(wire); {
		size := int(binary.BigEndian.Uint16(wire[off+3 : off+5]))
		payload = append(payload, wire[off+5:off+5+size]...)
		off += size + 5
	}
	digest := sha256.Sum256(payload)
	if want["client_hello_sha256"] != hex.EncodeToString(digest[:]) {
		t.Fatal("hash does not describe the original handshake bytes")
	}
	// The handshake header itself crosses a record boundary, and the remaining
	// records split variable-length fields at unrelated positions.
	var fragmented []byte
	for pos, chunk := 0, 1; pos < len(payload); chunk = 37 {
		end := pos + chunk
		if end > len(payload) {
			end = len(payload)
		}
		header := []byte{22, 3, 3, byte((end - pos) >> 8), byte(end - pos)}
		fragmented = append(fragmented, header...)
		fragmented = append(fragmented, payload[pos:end]...)
		pos = end
	}
	for end := 0; end < len(fragmented); end++ {
		_, done, err := parseClientHello(fragmented[:end])
		if err != nil || done {
			t.Fatalf("incomplete prefix %d reported complete/error: %v", end, err)
		}
	}
	got, done, err := parseClientHello(fragmented)
	if err != nil || !done || !reflect.DeepEqual(got, want) {
		t.Fatalf("record fragmentation changed observation: got=%+v want=%+v err=%v", got, want, err)
	}
	withLaterRecord := append(bytes.Clone(fragmented), []byte{23, 3, 3, 0, 1, 0}...)
	got, done, err = parseClientHello(withLaterRecord)
	if err != nil || !done || !reflect.DeepEqual(got, want) {
		t.Fatal("a later TLS record changed the first ClientHello")
	}
}

func TestClientHelloMalformedLengthsStayBounded(t *testing.T) {
	wrap := func(body []byte) []byte {
		hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
		return append([]byte{22, 3, 3, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	}
	fixed := append([]byte{3, 3}, make([]byte, 32)...)
	base := append(bytes.Clone(fixed), 0, 0, 2, 0x13, 1, 1, 0)
	for name, body := range map[string][]byte{
		"truncated fixed fields":  {3, 3},
		"truncated session ID":    append(bytes.Clone(fixed), 32, 1, 2),
		"odd cipher vector":       append(bytes.Clone(fixed), 0, 0, 3, 0x13, 1, 0, 1, 0),
		"truncated compression":   append(bytes.Clone(fixed), 0, 0, 2, 0x13, 1, 5, 0),
		"truncated extension len": append(bytes.Clone(base), 0),
		"short extension header":  append(bytes.Clone(base), 0, 1, 0),
		"short extension payload": append(bytes.Clone(base), 0, 5, 0, 43, 0, 20, 0),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseClientHello(wrap(body)); err == nil {
				t.Fatal("structurally incomplete ClientHello was accepted")
			}
		})
	}
	// Exercise arbitrary declared record/handshake lengths without network IO.
	// A panic fails the test; partial input is allowed to remain incomplete.
	random := rand.New(rand.NewSource(4402))
	for i := 0; i < 2000; i++ {
		wire := make([]byte, random.Intn(1024))
		_, _ = random.Read(wire)
		_, _, _ = parseClientHello(wire)
	}
}

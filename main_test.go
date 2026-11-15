package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// These tests construct and decode DNS independently of the production u16 and
// vector helpers. They verify the published wire format, not just byte equality
// with a second invocation of the implementation being tested.
func testDNSQuery(name string, typ uint16) []byte {
	b := []byte{0x71, 0x9a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, byte(typ>>8), byte(typ), 0, 1)
	return b
}

// Decode ordinary names and compressed pointers, including pointer-loop and
// bounds checks, so invalid response offsets cannot make a test pass by chance.
func testDNSName(b []byte, offset int) (string, int, error) {
	labels := []string{}
	seen := map[int]bool{}
	next := -1
	for {
		if offset >= len(b) || seen[offset] {
			return "", 0, fmt.Errorf("truncated or looping DNS name at %d", offset)
		}
		seen[offset] = true
		n := int(b[offset])
		offset++
		if n&0xc0 == 0xc0 {
			if offset >= len(b) {
				return "", 0, fmt.Errorf("truncated DNS pointer")
			}
			if next == -1 {
				next = offset + 1
			}
			offset = ((n & 0x3f) << 8) | int(b[offset])
			continue
		}
		if n == 0 {
			if next == -1 {
				next = offset
			}
			return strings.Join(labels, "."), next, nil
		}
		if n > 63 || offset+n > len(b) {
			return "", 0, fmt.Errorf("invalid DNS label length %d", n)
		}
		labels = append(labels, string(b[offset:offset+n]))
		offset += n
	}
}

type testDNSRecord struct {
	name string
	typ  uint16
	data []byte
}

func testDecodeAnswer(t *testing.T, query, reply []byte) []testDNSRecord {
	t.Helper()
	if len(reply) < 12 {
		t.Fatal("response is shorter than DNS header")
	}
	if !bytes.Equal(reply[:2], query[:2]) {
		t.Fatal("response does not preserve transaction ID")
	}
	flags := binary.BigEndian.Uint16(reply[2:4])
	if flags&0x8000 == 0 || flags&0x0200 != 0 || flags&0x000f != 0 {
		t.Fatalf("expected complete, successful DNS response; flags=%04x", flags)
	}
	if binary.BigEndian.Uint16(reply[4:6]) != 1 || !bytes.Equal(reply[8:12], []byte{0, 0, 0, 0}) {
		t.Fatal("expected one question and no authority/additional sections")
	}
	questionName, pos, err := testDNSName(reply, 12)
	if err != nil || pos+4 > len(reply) {
		t.Fatalf("invalid echoed question: %v", err)
	}
	if !bytes.Equal(reply[12:pos+4], query[12:]) {
		t.Fatal("response did not preserve the complete original question")
	}
	pos += 4
	answerCount := int(binary.BigEndian.Uint16(reply[6:8]))
	answers := make([]testDNSRecord, 0, answerCount)
	for i := 0; i < answerCount; i++ {
		name, afterName, err := testDNSName(reply, pos)
		if err != nil || afterName+10 > len(reply) {
			t.Fatalf("invalid answer header: %v", err)
		}
		if !strings.EqualFold(name, questionName) {
			t.Fatalf("answer owner %q differs from question %q", name, questionName)
		}
		typ := binary.BigEndian.Uint16(reply[afterName : afterName+2])
		class := binary.BigEndian.Uint16(reply[afterName+2 : afterName+4])
		length := int(binary.BigEndian.Uint16(reply[afterName+8 : afterName+10]))
		pos = afterName + 10
		if class != 1 || pos+length > len(reply) {
			t.Fatal("invalid answer class or RDLENGTH")
		}
		answers = append(answers, testDNSRecord{name, typ, reply[pos : pos+length]})
		pos += length
	}
	if pos != len(reply) {
		t.Fatalf("%d trailing bytes beyond declared DNS sections", len(reply)-pos)
	}
	return answers
}

func testHTTPSParams(t *testing.T, record testDNSRecord) map[uint16][]byte {
	t.Helper()
	if record.typ != 65 || len(record.data) < 3 || binary.BigEndian.Uint16(record.data[:2]) == 0 {
		t.Fatal("expected HTTPS ServiceMode record, not AliasMode")
	}
	name, pos, err := testDNSName(record.data, 2)
	expectedTarget := strings.ToLower(record.name)
	labels := strings.Split(expectedTarget, ".")
	if len(labels) > 2 && strings.HasPrefix(labels[0], "_") && labels[1] == "_https" {
		expectedTarget = strings.Join(labels[2:], ".")
	}
	if err != nil || name != expectedTarget {
		t.Fatalf("expected explicit service target %q, got %q: %v", expectedTarget, name, err)
	}
	params := map[uint16][]byte{}
	last := -1
	for pos < len(record.data) {
		if pos+4 > len(record.data) {
			t.Fatal("truncated SvcParam header")
		}
		key := binary.BigEndian.Uint16(record.data[pos : pos+2])
		length := int(binary.BigEndian.Uint16(record.data[pos+2 : pos+4]))
		pos += 4
		if int(key) <= last || pos+length > len(record.data) {
			t.Fatal("SvcParam keys must be unique and ordered, with valid lengths")
		}
		last = int(key)
		params[key] = record.data[pos : pos+length]
		pos += length
	}
	if !bytes.Equal(params[1], []byte{8, 'h', 't', 't', 'p', '/', '1', '.', '1'}) ||
		!bytes.Equal(params[4], []byte{127, 0, 0, 1}) {
		t.Fatal("HTTPS fixture must advertise TCP HTTP/1.1 and loopback IPv4 hint")
	}
	return params
}

func TestECHConfigEncodingAndKeyPair(t *testing.T) {
	material := newECH(17)
	b := material.Config
	if len(b) < 4 || binary.BigEndian.Uint16(b[:2]) != 0xfe0d || int(binary.BigEndian.Uint16(b[2:4])) != len(b)-4 {
		t.Fatal("ECHConfig has wrong version or content length")
	}
	b = b[4:]
	if len(b) < 5 || b[0] != 17 || binary.BigEndian.Uint16(b[1:3]) != 0x20 {
		t.Fatal("expected chosen config ID and X25519 HPKE KEM")
	}
	publicLength := int(binary.BigEndian.Uint16(b[3:5]))
	if publicLength != 32 || len(b) < 5+publicLength+9 {
		t.Fatal("invalid X25519 public key vector")
	}
	private, err := ecdh.X25519().NewPrivateKey(material.PrivateKey)
	if err != nil || !bytes.Equal(private.PublicKey().Bytes(), b[5:5+publicLength]) {
		t.Fatalf("ECH config public key does not match server private key: %v", err)
	}
	b = b[5+publicLength:]
	suitesLength := int(binary.BigEndian.Uint16(b[:2]))
	if suitesLength != 4 || !bytes.Equal(b[2:6], []byte{0, 1, 0, 1}) {
		t.Fatal("expected HPKE HKDF-SHA256 / AES-128-GCM suite")
	}
	b = b[2+suitesLength:]
	nameLength := int(b[1]) // maximum_name_length precedes public_name.
	if len(b) < 2+nameLength+2 || string(b[2:2+nameLength]) != "public.tlslab.test" {
		t.Fatal("invalid ECH public_name")
	}
	b = b[2+nameLength:]
	if len(b) != 2 || binary.BigEndian.Uint16(b) != 0 {
		t.Fatal("expected empty, correctly length-prefixed ECH extensions")
	}
}

func TestDNSHTTPSConfigLists(t *testing.T) {
	m := materials{Current: newECH(17), Old: newECH(16)}
	if bytes.Equal(m.Current.Config, m.Old.Config) || bytes.Equal(m.Current.PrivateKey, m.Old.PrivateKey) {
		t.Fatal("current and stale configurations require independent keys")
	}
	for _, tc := range []struct {
		name string
		want []byte
	}{
		{"valid.tlslab.test", m.Current.Config},
		{"stale.tlslab.test", m.Old.Config},
		{"baseline.tlslab.test", nil},
		{"_9443._https.valid.tlslab.test", m.Current.Config},
		{"_9443._https.stale.tlslab.test", m.Old.Config},
		{"_9443._https.baseline.tlslab.test", nil},
		{"_9443._HTTPS.VALID.TLSLAB.TEST", m.Current.Config},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := testDNSQuery(tc.name, 65)
			reply, name, typ, err := dnsResponse(query, m)
			if err != nil || name != strings.ToLower(tc.name) || typ != 65 {
				t.Fatalf("query metadata incorrect: name=%q type=%d err=%v", name, typ, err)
			}
			answers := testDecodeAnswer(t, query, reply)
			if len(answers) != 1 {
				t.Fatalf("expected one HTTPS answer, got %d", len(answers))
			}
			params := testHTTPSParams(t, answers[0])
			if len(params[3]) != 2 || binary.BigEndian.Uint16(params[3]) != 9443 {
				t.Fatal("ECH fixtures must point to port 9443")
			}
			list, present := params[5]
			if tc.want == nil {
				if present {
					t.Fatal("baseline must omit ech SvcParam entirely, not advertise an empty value")
				}
				return
			}
			if !present || len(list) < 2 || int(binary.BigEndian.Uint16(list[:2])) != len(list)-2 || !bytes.Equal(list[2:], tc.want) {
				t.Fatal("ech SvcParam must contain the correct, length-prefixed ECHConfigList")
			}
		})
	}
}

func TestDNSLoopbackAndNoExternalAnswers(t *testing.T) {
	m := materials{Current: newECH(17), Old: newECH(16)}
	for _, name := range []string{"valid.tlslab.test", "public.tlslab.test"} {
		query := testDNSQuery(name, 1)
		reply, _, _, err := dnsResponse(query, m)
		if err != nil {
			t.Fatal(err)
		}
		answers := testDecodeAnswer(t, query, reply)
		if len(answers) != 1 || answers[0].typ != 1 || !bytes.Equal(answers[0].data, []byte{127, 0, 0, 1}) {
			t.Fatal("A record must resolve only to the lab loopback address")
		}
	}
	for _, tc := range []struct {
		name string
		typ  uint16
	}{
		{"example.com", 1}, {"example.com", 65},
		{"valid.tlslab.test.example.com", 1}, {"eviltlslab.test", 65},
		{"not-a-fixture.tlslab.test", 1}, {"not-a-fixture.tlslab.test", 65},
		{"valid.tlslab.test", 28}, {"public.tlslab.test", 65},
	} {
		t.Run(fmt.Sprintf("%s/type%d", tc.name, tc.typ), func(t *testing.T) {
			query := testDNSQuery(tc.name, tc.typ)
			reply, _, _, err := dnsResponse(query, m)
			if err != nil {
				t.Fatal(err)
			}
			if answers := testDecodeAnswer(t, query, reply); len(answers) != 0 {
				t.Fatalf("unknown/unsupported name or type must have no answer; got %d", len(answers))
			}
		})
	}
}

func TestDNSFixturePorts(t *testing.T) {
	for _, tc := range []struct {
		name string
		port uint16
	}{
		{"tls10.tlslab.test", 9440},
		{"tls11.tlslab.test", 9441},
		{"tls12.tlslab.test", 9442},
		{"tls12-aes128.tlslab.test", 9445},
		{"tls12-chacha.tlslab.test", 9446},
		{"_9445._https.tls12-aes128.tlslab.test", 9445},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := testDNSQuery(tc.name, 65)
			reply, _, _, err := dnsResponse(query, materials{})
			if err != nil {
				t.Fatal(err)
			}
			answers := testDecodeAnswer(t, query, reply)
			if len(answers) != 1 {
				t.Fatalf("expected one HTTPS record, got %d", len(answers))
			}
			params := testHTTPSParams(t, answers[0])
			if len(params[3]) != 2 || binary.BigEndian.Uint16(params[3]) != tc.port {
				t.Fatalf("HTTPS port must select this fixture's actual listener %d; wire=%x", tc.port, params[3])
			}
			if _, present := params[5]; present {
				t.Fatal("TLS 1.0-1.2 fixtures must not advertise TLS 1.3 ECH")
			}
		})
	}
}

func TestDNSMalformedQueriesRejected(t *testing.T) {
	valid := testDNSQuery("valid.tlslab.test", 65)
	zeroQuestions := bytes.Clone(valid)
	zeroQuestions[5] = 0
	twoQuestions := bytes.Clone(valid)
	twoQuestions[5] = 2
	compressedLoop := append(bytes.Clone(valid[:12]), 0xc0, 0x0c, 0, 65, 0, 1)
	overlongName := testDNSQuery(strings.Repeat("a", 63)+"."+strings.Repeat("b", 63)+"."+strings.Repeat("c", 63)+"."+strings.Repeat("d", 63), 65)
	for name, query := range map[string][]byte{
		"empty":                        nil,
		"short header":                 valid[:11],
		"zero questions":               zeroQuestions,
		"two questions":                twoQuestions,
		"truncated label":              append(bytes.Clone(valid[:12]), 5, 'a'),
		"label over 63 octets":         testDNSQuery(strings.Repeat("a", 64)+".tlslab.test", 65),
		"name over 255 octets":         overlongName,
		"missing class byte":           valid[:len(valid)-1],
		"self-referential compression": compressedLoop,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := dnsResponse(query, materials{}); err == nil {
				t.Fatal("malformed DNS query was accepted")
			}
		})
	}
}

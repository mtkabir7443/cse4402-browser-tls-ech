package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// A non-default HTTPS port changes the RR owner to _port._https.host. A root
// TargetName would refer to that prefixed owner, not to the host's A/AAAA name.
// The explicit target must match the address owner so browsers can associate
// the ECH metadata with a usable endpoint without relying on address hints.
func TestHTTPSServiceTargetMatchesAddressOwner(t *testing.T) {
	m := materials{Current: newECH(17), Old: newECH(16)}
	for _, tc := range []struct {
		question string
		target   string
		port     uint16
		ech      []byte
	}{
		{"valid.tlslab.test", "valid.tlslab.test", 9443, m.Current.Config},
		{"_9443._https.valid.tlslab.test", "valid.tlslab.test", 9443, m.Current.Config},
		{"_9443._HTTPS.VALID.TLSLAB.TEST", "valid.tlslab.test", 9443, m.Current.Config},
		{"_9443._https.stale.tlslab.test", "stale.tlslab.test", 9443, m.Old.Config},
		{"_9443._https.baseline.tlslab.test", "baseline.tlslab.test", 9443, nil},
		{"_9451._https.tls13-aes128.tlslab.test", "tls13-aes128.tlslab.test", 9451, nil},
	} {
		t.Run(tc.question, func(t *testing.T) {
			question := testDNSQuery(tc.question, 65)
			reply, _, _, err := dnsResponse(question, m)
			if err != nil {
				t.Fatal(err)
			}
			answers := testDecodeAnswer(t, question, reply)
			if len(answers) != 1 {
				t.Fatalf("expected one HTTPS answer, got %d", len(answers))
			}
			if answers[0].data[2] == 0 {
				t.Fatal("root target would incorrectly inherit the _port._https owner")
			}
			target, _, err := testDNSName(answers[0].data, 2)
			if err != nil || target != tc.target || strings.HasPrefix(target, "_") {
				t.Fatalf("incorrect explicit target %q: %v", target, err)
			}
			params := testHTTPSParams(t, answers[0])
			if len(params[3]) != 2 || binary.BigEndian.Uint16(params[3]) != tc.port {
				t.Fatal("port parameter changed while correcting the target name")
			}
			if tc.ech == nil {
				if _, present := params[5]; present {
					t.Fatal("baseline/suite fixture unexpectedly advertises ECH")
				}
			} else {
				list := params[5]
				if len(list) < 2 || int(binary.BigEndian.Uint16(list[:2])) != len(list)-2 || !bytes.Equal(list[2:], tc.ech) {
					t.Fatal("explicit-target response lost or changed the selected ECHConfigList")
				}
			}
			addressQuestion := testDNSQuery(target, 1)
			addressReply, _, _, err := dnsResponse(addressQuestion, m)
			if err != nil {
				t.Fatal(err)
			}
			addresses := testDecodeAnswer(t, addressQuestion, addressReply)
			if len(addresses) != 1 || addresses[0].name != target || !bytes.Equal(addresses[0].data, []byte{127, 0, 0, 1}) {
				t.Fatal("HTTPS target and usable A-record owner must match")
			}
		})
	}
}

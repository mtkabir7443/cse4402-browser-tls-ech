package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

// Record only the first public ClientHello. This is wire evidence, not an ECH
// decryption oracle: actual acceptance still comes from crypto/tls state.
type helloConn struct {
	net.Conn
	captured []byte
	hello    map[string]any
	done     bool
}

func (c *helloConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if !c.done && n > 0 {
		if len(c.captured)+n > 131072 {
			c.done = true
		} else {
			c.captured = append(c.captured, p[:n]...)
			h, complete, err := parseClientHello(c.captured)
			if complete || err != nil {
				c.hello = h
				c.done = true
				c.captured = nil
			}
		}
	}
	return n, e
}
func parseClientHello(wire []byte) (map[string]any, bool, error) {
	var hs []byte
	for off := 0; off+5 <= len(wire); {
		if wire[off] != 22 {
			return nil, false, fmt.Errorf("not a handshake record")
		}
		length := int(binary.BigEndian.Uint16(wire[off+3 : off+5]))
		if off+5+length > len(wire) {
			return nil, false, nil
		}
		hs = append(hs, wire[off+5:off+5+length]...)
		off += 5 + length
		if len(hs) >= 4 {
			size := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if hs[0] != 1 {
				return nil, false, fmt.Errorf("not ClientHello")
			}
			if len(hs) >= 4+size {
				return decodeHello(hs[:4+size])
			}
		}
	}
	return nil, false, nil
}
func decodeHello(hs []byte) (map[string]any, bool, error) {
	bad := func() (map[string]any, bool, error) { return nil, true, fmt.Errorf("malformed ClientHello") }
	b := hs[4:]
	if len(b) < 35 {
		return bad()
	}
	off := 34
	sid := int(b[off])
	off++
	if off+sid+2 > len(b) {
		return bad()
	}
	off += sid
	count := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if count%2 != 0 || off+count+1 > len(b) {
		return bad()
	}
	suites := []string{}
	for end := off + count; off < end; off += 2 {
		suites = append(suites, fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(b[off:off+2])))
	}
	comp := int(b[off])
	off++
	if off+comp > len(b) {
		return bad()
	}
	off += comp
	digest := sha256.Sum256(hs)
	out := map[string]any{"offered_cipher_ids": suites, "client_hello_sha256": hex.EncodeToString(digest[:]), "ech_offered": false}
	if off == len(b) {
		return out, true, nil
	}
	if off+2 > len(b) {
		return bad()
	}
	extlen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+extlen != len(b) {
		return bad()
	}
	for off < len(b) {
		if off+4 > len(b) {
			return bad()
		}
		typ := binary.BigEndian.Uint16(b[off : off+2])
		size := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+size > len(b) {
			return bad()
		}
		v := b[off : off+size]
		off += size
		switch typ {
		case 0:
			if len(v) >= 5 && v[2] == 0 {
				n := int(binary.BigEndian.Uint16(v[3:5]))
				if 5+n <= len(v) {
					out["outer_server_name"] = string(v[5 : 5+n])
				}
			}
		case 43:
			if len(v) > 0 && int(v[0])+1 == len(v) && v[0]%2 == 0 {
				versions := []string{}
				for i := 1; i+1 < len(v); i += 2 {
					versions = append(versions, fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(v[i:i+2])))
				}
				out["offered_version_ids"] = versions
			}
		case 0xfe0d:
			out["ech_offered"] = true
			out["ech_extension_length"] = len(v)
			if len(v) >= 6 && v[0] == 0 {
				out["ech_config_id"] = int(v[5])
			}
		}
	}
	return out, true, nil
}

package tlsx

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/karthick-kk/kubeshark-oss/tap/api"
)

// buildClientHello builds a wire-faithful TLS 1.2 ClientHello record:
// 5-byte record header, 4-byte handshake header, fixed 32-byte client part,
// the given SNI and ALPN extensions, and a trailing session-id block so the
// lengths line up.
func buildClientHello(t *testing.T, sni string, alpn []string) []byte {
	t.Helper()

	var exts []byte
	// addExt appends a TLS extension: type(2) data_len(2) data.
	addExt := func(extType uint16, data []byte) {
		var tl, dl [2]byte
		binary.BigEndian.PutUint16(tl[:], extType)
		binary.BigEndian.PutUint16(dl[:], uint16(len(data)))
		exts = append(exts, tl[:]...)
		exts = append(exts, dl[:]...)
		exts = append(exts, data...)
	}
	if sni != "" {
		name := []byte(sni)
		// one ServerName entry: name_type(1)=host_name, hostname_len(2), hostname
		entry := []byte{0x00}
		var nl [2]byte
		binary.BigEndian.PutUint16(nl[:], uint16(len(name)))
		entry = append(entry, nl[:]...)
		entry = append(entry, name...)
		// server_name_list = list_len(2) + entry (RFC 6066)
		var listLen [2]byte
		binary.BigEndian.PutUint16(listLen[:], uint16(len(entry)))
		data := append(listLen[:], entry...)
		addExt(0x0000, data)
	}
	if len(alpn) > 0 {
		// PreferredApplicationProtocol = list_len(2) + protocols (1-byte len + proto)
		var protos []byte
		for _, a := range alpn {
			protos = append(protos, byte(len(a)))
			protos = append(protos, a...)
		}
		var listLen [2]byte
		binary.BigEndian.PutUint16(listLen[:], uint16(len(protos)))
		data := append(listLen[:], protos...)
		addExt(0x0010, data)
	}
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(exts)))

	// client_version(2) random(32) session_id_len(1)=0 cipher_len(2) ciphers(6)
	// compression_len(1)=1 compression(1)=0 -> fixed prefix is 45 bytes,
	// extensions follow at offset 45.
	body := make([]byte, 0, 45+2+len(exts))
	body = append(body, 0x03, 0x03)          // client_version TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id len 0
	var cs [2]byte
	binary.BigEndian.PutUint16(cs[:], 6) // 3 cipher suites (6 bytes)
	body = append(body, cs[:]...)
	body = append(body, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
	body = append(body, 0x01) // compression list len 1
	body = append(body, 0x00) // compression: null
	body = append(body, extLen[:]...)
	body = append(body, exts...)

	var hs [4]byte
	hs[0] = 0x01 // handshake type: ClientHello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))

	var recLen [2]byte
	binary.BigEndian.PutUint16(recLen[:], uint16(4+len(body)))

	rec := []byte{0x16, 0x03, 0x01} // content type handshake, version TLS 1.0 (common on the wire)
	rec = append(rec, recLen[:]...)
	rec = append(rec, hs[:]...)
	rec = append(rec, body...)
	return rec
}

func TestParseClientHelloSNIALPN(t *testing.T) {
	rec := buildClientHello(t, "login.example.com", []string{"h2", "http/1.1"})
	b := bufio.NewReader(bytes.NewReader(rec))
	if _, err := readTLSRecordHeader(b); err != nil {
		t.Fatalf("readTLSRecordHeader: %v", err)
	}
	info, hsType, err := parseHandshake(b)
	if err != nil {
		t.Fatalf("parseHandshake: %v", err)
	}
	if hsType != 0x01 {
		t.Fatalf("handshake type = 0x%02x, want 0x01", hsType)
	}
	if !info.IsClient {
		t.Fatal("IsClient = false")
	}
	if info.SNI != "login.example.com" {
		t.Fatalf("SNI = %q, want login.example.com", info.SNI)
	}
	if len(info.ALPN) != 2 || info.ALPN[0] != "h2" || info.ALPN[1] != "http/1.1" {
		t.Fatalf("ALPN = %v", info.ALPN)
	}
	if info.CipherSuites != 3 {
		t.Fatalf("CipherSuites = %d, want 3", info.CipherSuites)
	}
	if info.ClientVer != 0x0303 {
		t.Fatalf("ClientVer = 0x%04x, want 0x0303", info.ClientVer)
	}
}

func TestParseClientHelloNoExtensions(t *testing.T) {
	rec := buildClientHello(t, "", nil)
	b := bufio.NewReader(bytes.NewReader(rec))
	if _, err := readTLSRecordHeader(b); err != nil {
		t.Fatalf("readTLSRecordHeader: %v", err)
	}
	info, hsType, err := parseHandshake(b)
	if err != nil {
		t.Fatalf("parseHandshake: %v", err)
	}
	if hsType != 0x01 {
		t.Fatalf("handshake type = 0x%02x, want 0x01", hsType)
	}
	if info.SNI != "" || len(info.ALPN) != 0 {
		t.Fatalf("expected no SNI/ALPN, got %q / %v", info.SNI, info.ALPN)
	}
	if info.CipherSuites != 3 {
		t.Fatalf("CipherSuites = %d, want 3", info.CipherSuites)
	}
}

func TestParseRejectsNonHandshake(t *testing.T) {
	// A Certificate message (type 0x14) inside a 0x16 record is not a
	// ClientHello/ServerHello, so parseHandshake must reject it — the caller
	// then leaves the stream unclaimed for the rawtcp fallback.
	rec := buildClientHello(t, "x.example", nil)
	rec[5] = 0x14 // handshake type: Certificate, not Client/ServerHello
	b := bufio.NewReader(bytes.NewReader(rec))
	if _, err := readTLSRecordHeader(b); err != nil {
		t.Fatalf("readTLSRecordHeader: %v", err)
	}
	if _, _, err := parseHandshake(b); err == nil {
		t.Fatal("expected an error for a non-handshake TLS type")
	}
}

func TestParseAcceptsServerHello(t *testing.T) {
	// A ServerHello (type 0x02) is a genuine TLS handshake — accepted with no
	// parsed body detail.
	rec := buildClientHello(t, "x.example", nil)
	rec[5] = 0x02 // handshake type: ServerHello
	b := bufio.NewReader(bytes.NewReader(rec))
	if _, err := readTLSRecordHeader(b); err != nil {
		t.Fatalf("readTLSRecordHeader: %v", err)
	}
	info, hsType, err := parseHandshake(b)
	if err != nil {
		t.Fatalf("parseHandshake: %v", err)
	}
	if hsType != 0x02 {
		t.Fatalf("handshake type = 0x%02x, want 0x02", hsType)
	}
	if info.IsClient {
		t.Fatal("ServerHello must not be parsed as a client hello")
	}
}

// TestRepresentShape pins the Represent contract the stock UI depends on:
// representation must parse to {request, response} where request is a SectionData
// array (the UI calls .entries() on it — a plain object throws and blanks the page).
func TestRepresentShape(t *testing.T) {
	d := dissecting{}
	request := map[string]interface{}{
		"type":      "tlsx",
		"recordVer": 769,
		"sni":       "oauth.aigw.vcs.local",
		"alpn":      []string{"http/1.1"},
		"ciphers":   9,
		"clientVer": 771,
	}
	rep, err := d.Represent(request, nil)
	if err != nil {
		t.Fatalf("Represent: %v", err)
	}
	var repMap map[string]json.RawMessage
	if err := json.Unmarshal(rep, &repMap); err != nil {
		t.Fatalf("representation not an object: %v", err)
	}
	var secs []api.SectionData
	if err := json.Unmarshal(repMap["request"], &secs); err != nil {
		t.Fatalf("request is not a SectionData array (UI would call .entries() on an object and crash): %v; raw: %s", err, string(repMap["request"]))
	}
	if len(secs) == 0 {
		t.Fatal("request has no sections")
	}
	if secs[0].Type != api.TABLE {
		t.Fatalf("request[0].type = %q, want table", secs[0].Type)
	}
	if secs[0].Data == "" {
		t.Fatal("request[0].data empty")
	}
	var resp []interface{}
	if err := json.Unmarshal(repMap["response"], &resp); err != nil {
		t.Fatalf("response is not an array: %v; raw: %s", err, string(repMap["response"]))
	}
}

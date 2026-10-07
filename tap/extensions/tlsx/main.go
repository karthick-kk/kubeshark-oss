package tlsx

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/karthick-kk/kubeshark-oss/tap/api"
)

// Priority 50 — after the L7 dissectors (http/amqp/kafka/redis, 0-3), before the
// rawtcp catch-all (99). It claims a stream the moment the first TLS handshake
// record is seen, so a TLS connection surfaces as one handshake entry (with
// SNI/ALPN/version when the client leg is first) instead of falling through to
// rawtcp. The encrypted body is left for the stream closer / TLS tapper.
var protocol = api.Protocol{
	ProtocolSummary: api.ProtocolSummary{
		Name:         "tls",
		Version:      "1.2",
		Abbreviation: "TLS",
	},
	LongName:        "TLS Handshake",
	Macro:           "tls",
	BackgroundColor: "#0f9d58",
	ForegroundColor: "#ffffff",
	FontSize:        12,
	ReferenceLink:   "https://datatracker.ietf.org/doc/html/rfc8446",
	Ports:           []string{"443", "8443"},
	Priority:        50,
}

var protocolsMap = map[string]*api.Protocol{
	protocol.ToString(): &protocol,
}

const (
	tlsHandshake    = 0x16
	tlsRecordMinLen = 5
	clientHelloType = 0x01
	maxHandshakeLen = 16384
)

type tlsHeader struct {
	ContentType byte
	Version     uint16
	Length      uint16
}

// readTLSRecordHeader parses one 5-byte TLS record header.
func readTLSRecordHeader(r *bufio.Reader) (tlsHeader, error) {
	var head [tlsRecordMinLen]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return tlsHeader{}, err
	}
	return tlsHeader{
		ContentType: head[0],
		Version:     binary.BigEndian.Uint16(head[1:3]),
		Length:      binary.BigEndian.Uint16(head[3:5]),
	}, nil
}

type clientHelloInfo struct {
	SNI          string
	ALPN         []string
	CipherSuites int
	RecordVer    uint16
	ClientVer    uint16
	IsClient     bool
}

// parseHandshake reads one handshake following a 0x16 record header and
// returns its type plus, for a ClientHello, the parsed SNI/ALPN/cipher details.
// A type that is not a ClientHello/ServerHello returns an error so the caller
// does not claim the stream. It is lenient: a truncated body yields a partial
// (but valid) result rather than an error.
func parseHandshake(b *bufio.Reader) (clientHelloInfo, byte, error) {
	var out clientHelloInfo

	var h [4]byte
	if _, err := io.ReadFull(b, h[:]); err != nil {
		return out, 0, err
	}
	hsType := h[0]
	switch hsType {
	case clientHelloType, 0x02 /* ServerHello */ :
	default:
		return out, hsType, fmt.Errorf("not a TLS handshake (type 0x%02x)", hsType)
	}
	if hsType != clientHelloType {
		return out, hsType, nil // ServerHello — real TLS, nothing to parse
	}

	hsLen := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	if hsLen < 41 || hsLen > maxHandshakeLen {
		return out, hsType, fmt.Errorf("implausible ClientHello length %d", hsLen)
	}

	body := make([]byte, hsLen)
	if _, err := io.ReadFull(b, body); err != nil {
		return out, hsType, err
	}
	// ClientHello prefix (walked, not hardcoded, because session_id and
	// cipher-suite lists are variable length):
	// client_version(2) random(32) session_id_len(1) session_id(n)
	// cipher_suites_len(2) ciphers(n) compression_len(1) compression(n)
	// extensions_len(2) extensions(...)
	out.ClientVer = binary.BigEndian.Uint16(body[0:2])

	p := 2 + 32
	sessIDLen := int(body[p])
	p++
	if p+sessIDLen+2 > len(body) {
		return out, hsType, nil // truncated; keep partial
	}
	p += sessIDLen
	cipherLen := int(body[p])<<8 | int(body[p+1])
	p += 2
	out.CipherSuites = cipherLen / 2
	if p+cipherLen+1 > len(body) {
		return out, hsType, nil
	}
	p += cipherLen
	compLen := int(body[p])
	p++
	if p+compLen+2 > len(body) {
		return out, hsType, nil
	}
	p += compLen
	totalExt := int(body[p])<<8 | int(body[p+1])
	extOff := p + 2
	if extOff+totalExt > len(body) {
		return out, hsType, nil // extensions truncated; keep partial
	}
	off := extOff
	end := extOff + totalExt
	for off+4 <= end {
		et := int(body[off])<<8 | int(body[off+1])
		el := int(body[off+2])<<8 | int(body[off+3])
		off += 4
		if off+el > end {
			break
		}
		data := body[off : off+el]
		off += el
		switch et {
		case 0x00: // server_name
			if sni, ok := parseSNI(data); ok {
				out.SNI = sni
			}
		case 0x10: // alpn
			out.ALPN = parseALPN(data)
		}
	}
	out.IsClient = true
	return out, hsType, nil
}

func parseSNI(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	listLen := int(data[0])<<8 | int(data[1])
	if 2+listLen > len(data) {
		return "", false
	}
	i := 2
	for i+1 < len(data) {
		nameType := data[i]
		i++
		if i+2 > len(data) {
			break
		}
		nl := int(data[i])<<8 | int(data[i+1])
		i += 2
		if i+nl > len(data) {
			break
		}
		name := string(data[i : i+nl])
		i += nl
		if nameType == 0x00 && name != "" {
			return name, true
		}
	}
	return "", false
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	if 2+listLen > len(data) {
		return nil
	}
	off := 2
	var out []string
	for off < 2+listLen {
		if off >= len(data) {
			break
		}
		pl := int(data[off])
		off++
		if off+pl > len(data) {
			break
		}
		out = append(out, string(data[off:off+pl]))
		off += pl
	}
	return out
}

type dissecting struct{}

func (d dissecting) Register(extension *api.Extension) {
	extension.Protocol = &protocol
}

func (d dissecting) GetProtocols() map[string]*api.Protocol {
	return protocolsMap
}

func (d dissecting) Ping() {
	log.Printf("pong %s", protocol.Name)
}

// Dissect runs on both legs of the connection. Each leg claims the stream on
// the first TLS handshake record (so the chain stops and rawtcp does not also
// emit). Only the client leg emits: it is the leg that read the ClientHello,
// i.e. the only one with SNI/ALPN/cipher detail. The server leg's first
// record is a ServerHello with none of that, so a latch race between the two
// legs would sometimes emit an empty entry — leg direction is the
// deterministic emit side.
func (d dissecting) Dissect(b *bufio.Reader, reader api.TcpReader, options *api.TrafficFilteringOptions) error {
	rec, err := readTLSRecordHeader(b)
	if err != nil {
		return err
	}
	if rec.ContentType != tlsHandshake {
		// Not TLS — leave the stream unclaimed so the next dissector (rawtcp)
		// handles it.
		return fmt.Errorf("not a TLS record (content type 0x%02x)", rec.ContentType)
	}

	info, _, perr := parseHandshake(b)
	if perr != nil {
		// Not a genuine TLS handshake — leave the stream unclaimed so rawtcp
		// handles it (a 0x16 first byte on a non-TLS stream would otherwise be
		// mislabeled as TLS).
		return perr
	}

	// Claim the stream so the extension chain stops here and rawtcp will not
	// emit a duplicate entry for the same connection. Both legs claim; only the
	// client leg emits — it is the one that read the ClientHello (SNI/ALPN), so
	// gating the emit on leg direction is deterministic (a latch race would
	// sometimes let the server leg win and emit an empty entry).
	reader.GetParent().SetProtocol(&protocol)
	if !reader.GetIsClient() {
		return nil
	}

	tcpID := reader.GetTcpID()
	first := reader.GetCaptureTime()

	// Normalize to the TCP client (initiator) -> server (responder) direction so
	// the 5-tuple is deterministic regardless of which leg won the latch.
	var clientIP, clientPort, serverIP, serverPort string
	if reader.GetIsClient() {
		clientIP, clientPort = tcpID.SrcIP, tcpID.SrcPort
		serverIP, serverPort = tcpID.DstIP, tcpID.DstPort
	} else {
		clientIP, clientPort = tcpID.DstIP, tcpID.DstPort
		serverIP, serverPort = tcpID.SrcIP, tcpID.SrcPort
	}

	payload := map[string]interface{}{
		"type":      "tlsx",
		"recordVer": rec.Version,
	}
	if info.IsClient {
		payload["sni"] = info.SNI
		payload["alpn"] = info.ALPN
		payload["ciphers"] = info.CipherSuites
		payload["clientVer"] = info.ClientVer
	} else {
		payload["sni"] = ""
		payload["alpn"] = []string{}
		payload["ciphers"] = 0
		payload["clientVer"] = uint16(0)
	}

	item := &api.OutputChannelItem{
		Protocol:  protocol,
		Timestamp: first.UnixNano() / int64(time.Millisecond),
		Capture:   reader.GetParent().GetOrigin(),
		Pair: &api.RequestResponsePair{
			Request: api.GenericMessage{
				IsRequest:   true,
				CaptureTime: first,
				CaptureSize: 0,
				Payload:     payload,
			},
			Response: api.GenericMessage{
				IsRequest:   false,
				CaptureTime: first,
				CaptureSize: 0,
				Payload:     map[string]interface{}{},
			},
		},
	}
	item.ConnectionInfo = &api.ConnectionInfo{
		ClientIP:   clientIP,
		ClientPort: clientPort,
		ServerIP:   serverIP,
		ServerPort: serverPort,
		// Intentionally false: the api FilterItems path drops outgoing->serviceIP
		// entries; a TLS leg to a k8s service IP (e.g. keycloak :8443) must stay.
		IsOutgoing: false,
	}

	reader.GetEmitter().Emit(item)
	return nil
}

func (d dissecting) Analyze(item *api.OutputChannelItem, resolvedSource string, resolvedDestination string, namespace string) *api.Entry {
	request := item.Pair.Request.Payload.(map[string]interface{})
	response := item.Pair.Response.Payload.(map[string]interface{})

	// If the destination didn't resolve to a pod, the SNI is the target the
	// client dialed — use it for display.
	if resolvedDestination == "" {
		if sni, _ := request["sni"].(string); sni != "" {
			resolvedDestination = sni
		}
	}

	return &api.Entry{
		Id: fmt.Sprintf("tlsx_%s_%s_%s_%s",
			item.ConnectionInfo.ClientIP, item.ConnectionInfo.ClientPort,
			item.ConnectionInfo.ServerIP, item.ConnectionInfo.ServerPort),
		Protocol:    protocol.ProtocolSummary,
		Capture:     item.Capture,
		Source:      &api.TCP{Name: resolvedSource, IP: item.ConnectionInfo.ClientIP, Port: item.ConnectionInfo.ClientPort},
		Destination: &api.TCP{Name: resolvedDestination, IP: item.ConnectionInfo.ServerIP, Port: item.ConnectionInfo.ServerPort},
		Namespace:   namespace,
		Outgoing:    item.ConnectionInfo.IsOutgoing,
		Request:     request,
		Response:    response,
		Timestamp:   item.Timestamp,
		StartTime:   item.Pair.Request.CaptureTime,
	}
}

func (d dissecting) Summarize(entry *api.Entry) *api.BaseEntry {
	sni, _ := entry.Request["sni"].(string)
	return &api.BaseEntry{
		Id:          entry.Id,
		Protocol:    *protocolsMap[entry.Protocol.ToString()],
		Capture:     entry.Capture,
		Summary:     sni,
		Timestamp:   entry.Timestamp,
		Source:      entry.Source,
		Destination: entry.Destination,
		IsOutgoing:  entry.Outgoing,
	}
}

// The UI (SectionsRepresentation) calls .entries() on the parsed request/response,
// so Represent must emit the stock shape: request/response are arrays of
// api.SectionData (a "table" section whose Data is a JSON string of []TableData).
// Emitting the raw payload object instead makes .entries() throw and blanks the
// whole app.
func (d dissecting) Represent(request map[string]interface{}, response map[string]interface{}) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"request":  representRequest(request),
		"response": []interface{}{},
	})
}

func representRequest(request map[string]interface{}) []interface{} {
	if request == nil {
		return []interface{}{}
	}
	details, _ := json.Marshal([]api.TableData{
		{Name: "Record Version", Value: request["recordVer"], Selector: "request.recordVer"},
		{Name: "SNI", Value: request["sni"], Selector: "request.sni"},
		{Name: "ALPN", Value: request["alpn"], Selector: "request.alpn"},
		{Name: "Cipher Suites", Value: request["ciphers"], Selector: "request.ciphers"},
		{Name: "Client Version", Value: request["clientVer"], Selector: "request.clientVer"},
	})
	return []interface{}{
		api.SectionData{Type: api.TABLE, Title: "Details", Data: string(details)},
	}
}

func (d dissecting) Macros() map[string]string {
	return map[string]string{
		`tls`: fmt.Sprintf(`protocol.name == "%s"`, protocol.Name),
	}
}

func (d dissecting) NewResponseRequestMatcher() api.RequestResponseMatcher {
	return &tlsxMatcher{openMessagesMap: &sync.Map{}}
}

// tlsxMatcher is a no-op request/response matcher: tlsx emits a single
// handshake entry and never pairs requests with responses.
type tlsxMatcher struct {
	openMessagesMap *sync.Map
}

func (m *tlsxMatcher) GetMap() *sync.Map { return m.openMessagesMap }
func (m *tlsxMatcher) SetMaxTry(_ int)   {}

var Dissector dissecting

func NewDissector() api.Dissector {
	return Dissector
}

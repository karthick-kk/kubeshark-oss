package rawtcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/karthick-kk/kubeshark-oss/tap/api"
)

// priority 99 — a terminal fallback. It is only reached when no higher-priority
// dissection (http/amqp/kafka/redis) claimed the stream, i.e. the payload did
// not match any known L7 protocol. This is what makes raw-TCP / opaque-TLS
// connections (keycloak :8443, contour :443 legs, ...) visible at all.
var protocol = api.Protocol{
	ProtocolSummary: api.ProtocolSummary{
		Name:         "tcp",
		Version:      "v4",
		Abbreviation: "TCP",
	},
	LongName:        "Raw TCP (no protocol identified)",
	Macro:           "tcp",
	BackgroundColor: "#607d8b",
	ForegroundColor: "#ffffff",
	FontSize:        12,
	ReferenceLink:   "https://datatracker.ietf.org/doc/html/rfc0793",
	Ports:           []string{"*"},
	Priority:        99,
}

var protocolsMap = map[string]*api.Protocol{
	protocol.ToString(): &protocol,
}

// sampleCap bounds how much of the payload we keep for display, so a huge
// transfer can never balloon memory or the entry.
const sampleCap = 128

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

// Dissect runs on BOTH legs of the connection (client and server readers each
// walk the extension chain, and this terminal fallback is reached on a stream
// no higher-priority dissector identified). It claims the stream so the chain
// stops and the stream is not treated as "unidentified" by the closer, then a
// single flow-level entry is emitted.
//
// Exactly-once: the client and server legs race, and SetProtocol is shared
// per-connection, so whichever leg reaches rawtcp first can break the other
// leg's loop before it gets here. We gate the emit on the per-connection
// matcher (shared by both legs) so exactly one leg wins and emits.
//
// ponytail: reports the byte count of the one leg that won the latch, not both
// directions. Bidirectional byte totals would need a shared per-connection
// aggregator (upgrade: accumulate in both legs behind the stream mutex, emit
// once at close).
func (d dissecting) Dissect(b *bufio.Reader, reader api.TcpReader, options *api.TrafficFilteringOptions) error {
	reader.GetParent().SetProtocol(&protocol)

	// Exactly-once emit: the client and server legs each walk this extension on
	// their own goroutine, and SetProtocol is shared per-connection, so a race
	// lets both legs reach here. The per-connection matcher (shared by both legs)
	// claims the emit once.
	rawMatcher := reader.GetReqResMatcher().(*rawMatcher)
	if !rawMatcher.claimEmit() {
		return nil
	}

	buf := make([]byte, 64*1024)
	var total int
	var sample []byte
	var first, last time.Time
	for {
		n, err := b.Read(buf)
		if n > 0 {
			total += n
			if len(sample) < sampleCap {
				want := sampleCap - len(sample)
				if n < want {
					want = n
				}
				sample = append(sample, buf[:want]...)
			}
			t := reader.GetCaptureTime()
			if first.IsZero() {
				first = t
			}
			last = t
		}
		if err != nil {
			break
		}
	}

	if total == 0 {
		return nil
	}

	durationMs := int64(0)
	if !last.IsZero() && !first.IsZero() {
		durationMs = last.Sub(first).Round(time.Millisecond).Milliseconds()
	}

	// Normalize to capture order (first-packet src -> dst) regardless of which
	// leg won the latch, so the 5-tuple direction is deterministic.
	tcpID := reader.GetTcpID()
	var clientIP, clientPort, serverIP, serverPort string
	if reader.GetIsClient() {
		clientIP, clientPort = tcpID.SrcIP, tcpID.SrcPort
		serverIP, serverPort = tcpID.DstIP, tcpID.DstPort
	} else {
		clientIP, clientPort = tcpID.DstIP, tcpID.DstPort
		serverIP, serverPort = tcpID.SrcIP, tcpID.SrcPort
	}
	item := &api.OutputChannelItem{
		Protocol:  protocol,
		Timestamp: first.UnixNano() / int64(time.Millisecond),
		Pair: &api.RequestResponsePair{
			Request: api.GenericMessage{
				IsRequest:   true,
				CaptureTime: first,
				CaptureSize: total,
				Payload: map[string]interface{}{
					"type":       "rawtcp",
					"bytes":      total,
					"sample":     printableSample(sample),
					"durationMs": durationMs,
				},
			},
			Response: api.GenericMessage{
				IsRequest:   false,
				CaptureTime: last,
				CaptureSize: 0,
				Payload:     map[string]interface{}{},
			},
		},
	}
	item.Capture = reader.GetParent().GetOrigin()
	item.ConnectionInfo = &api.ConnectionInfo{
		ClientIP:   clientIP,
		ClientPort: clientPort,
		ServerIP:   serverIP,
		ServerPort: serverPort,
		// Intentionally false: the api FilterItems path drops outgoing->serviceIP
		// entries; rawtcp is the fallback that must stay visible for those legs.
		IsOutgoing: false,
	}

	reader.GetEmitter().Emit(item)
	return nil
}

func (d dissecting) Analyze(item *api.OutputChannelItem, resolvedSource string, resolvedDestination string, namespace string) *api.Entry {
	request := item.Pair.Request.Payload.(map[string]interface{})
	response := item.Pair.Response.Payload.(map[string]interface{})

	// durationMs is int64 in-process and float64 after the tapper->API JSON
	// round-trip; accept both.
	var elapsedTime int64
	switch v := request["durationMs"].(type) {
	case float64:
		elapsedTime = int64(v)
	case int64:
		elapsedTime = v
	}

	return &api.Entry{
		Id: fmt.Sprintf("rawtcp_%s_%s_%s_%s",
			item.ConnectionInfo.ClientIP, item.ConnectionInfo.ClientPort,
			item.ConnectionInfo.ServerIP, item.ConnectionInfo.ServerPort),
		Protocol: protocol.ProtocolSummary,
		Capture:  item.Capture,
		Source: &api.TCP{
			Name: resolvedSource,
			IP:   item.ConnectionInfo.ClientIP,
			Port: item.ConnectionInfo.ClientPort,
		},
		Destination: &api.TCP{
			Name: resolvedDestination,
			IP:   item.ConnectionInfo.ServerIP,
			Port: item.ConnectionInfo.ServerPort,
		},
		Namespace:    namespace,
		Outgoing:     item.ConnectionInfo.IsOutgoing,
		Request:      request,
		Response:     response,
		RequestSize:  item.Pair.Request.CaptureSize,
		ResponseSize: 0,
		Timestamp:    item.Timestamp,
		StartTime:    item.Pair.Request.CaptureTime,
		ElapsedTime:  elapsedTime,
	}
}

func (d dissecting) Summarize(entry *api.Entry) *api.BaseEntry {
	sample, _ := entry.Request["sample"].(string)
	return &api.BaseEntry{
		Id:          entry.Id,
		Protocol:    *protocolsMap[entry.Protocol.ToString()],
		Capture:     entry.Capture,
		Summary:     sample,
		Timestamp:   entry.Timestamp,
		Source:      entry.Source,
		Destination: entry.Destination,
		IsOutgoing:  entry.Outgoing,
		Latency:     entry.ElapsedTime,
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
		{Name: "Bytes", Value: request["bytes"], Selector: "request.bytes"},
		{Name: "Duration (ms)", Value: request["durationMs"], Selector: "request.durationMs"},
		{Name: "Payload Sample", Value: request["sample"], Selector: "request.sample"},
	})
	return []interface{}{
		api.SectionData{Type: api.TABLE, Title: "Details", Data: string(details)},
	}
}

func (d dissecting) Macros() map[string]string {
	return map[string]string{
		`tcp`: fmt.Sprintf(`protocol.name == "%s"`, protocol.Name),
	}
}

func (d dissecting) NewResponseRequestMatcher() api.RequestResponseMatcher {
	return &rawMatcher{openMessagesMap: &sync.Map{}}
}

// rawMatcher is a no-op matcher for pairing (rawtcp emits a single flow entry,
// it never pairs requests with responses). Its only job is the sync.Once emit
// latch shared by the two legs of a connection.
type rawMatcher struct {
	openMessagesMap *sync.Map
	emitOnce        sync.Once
}

func (m *rawMatcher) GetMap() *sync.Map { return m.openMessagesMap }

func (m *rawMatcher) SetMaxTry(_ int) {}

// claimEmit returns true for exactly one of the two legs of a connection.
func (m *rawMatcher) claimEmit() bool {
	claimed := false
	m.emitOnce.Do(func() { claimed = true })
	return claimed
}

// printableSample renders a payload sample as a printable string, replacing
// non-ASCII bytes with '.' so binary/TLS records are UI-safe.
func printableSample(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

var Dissector dissecting

func NewDissector() api.Dissector {
	return Dissector
}

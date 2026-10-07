package rawtcp

import (
	"bufio"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/karthick-kk/kubeshark-oss/tap/api"
)

// TestDissectEmitsFlowEntry drives rawtcp's Dissect the same way
// tap/tcp_reader.go run() does for the terminal extension: feed the reassembled
// bytes, then EOF (connection closed). It asserts one flow entry is emitted
// with the client->server 5-tuple and the byte count. This isolates the
// emit logic from the live cluster (BPF filter, throttle, reassembly, the
// http/tlsx extensions that precede it in the chain).
func TestDissectEmitsFlowEntry(t *testing.T) {
	payload := []byte("RAWTCPMARKER12345RAWTCP")

	emitted := make(chan *api.OutputChannelItem, 4)
	stream := &mockStream{origin: api.Pcap}
	reader := &mockReader{
		data:   append([]byte(nil), payload...),
		tcpID:  &api.TcpID{SrcIP: "10.244.0.46", DstIP: "10.244.0.45", SrcPort: "50000", DstPort: "8899"},
		parent: stream,
		matcher: &rawMatcher{
			openMessagesMap: &sync.Map{},
		},
	}
	reader.isClient = true
	reader.emitter = &api.Emitting{AppStats: &api.AppStats{}, OutputChannel: emitted}

	d := NewDissector()
	if err := d.Dissect(bufio.NewReader(reader), reader, &api.TrafficFilteringOptions{IgnoredUserAgents: []string{}}); err != nil {
		t.Fatalf("Dissect returned error: %v", err)
	}

	select {
	case item := <-emitted:
		if item.Protocol.Name != "tcp" {
			t.Fatalf("protocol = %q, want tcp", item.Protocol.Name)
		}
		ci := item.ConnectionInfo
		if ci.ClientIP != "10.244.0.46" || ci.ServerIP != "10.244.0.45" || ci.ClientPort != "50000" || ci.ServerPort != "8899" {
			t.Fatalf("5-tuple wrong: %+v", ci)
		}
		req := item.Pair.Request.Payload.(map[string]interface{})
		if req["bytes"] != len(payload) {
			t.Fatalf("bytes = %v, want %d", req["bytes"], len(payload))
		}
		if stream.protocol == nil || stream.protocol.Name != "tcp" {
			t.Fatalf("stream protocol not set to tcp (got %v)", stream.protocol)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Dissect returned without emitting a flow entry")
	}

	// A second leg on the same connection (shared matcher) must NOT emit again.
	reader2 := &mockReader{
		tcpID:  &api.TcpID{SrcIP: "10.244.0.45", DstIP: "10.244.0.46", SrcPort: "8899", DstPort: "50000"},
		parent: stream,
		matcher: reader.matcher,
	}
	reader2.isClient = false
	reader2.emitter = &api.Emitting{AppStats: &api.AppStats{}, OutputChannel: emitted}
	if err := d.Dissect(bufio.NewReader(reader2), reader2, &api.TrafficFilteringOptions{IgnoredUserAgents: []string{}}); err != nil {
		t.Fatalf("Dissect (2nd leg) returned error: %v", err)
	}
	select {
	case item := <-emitted:
		t.Fatalf("second leg emitted a duplicate entry: %+v", item.Protocol)
	case <-time.After(200 * time.Millisecond):
		// expected: exactly-once latch held
	}
}

// TestDissectEmitsNothingWhenEmpty verifies a leg that saw zero bytes emits
// nothing (matches the `total == 0` guard) — this is the degenerate case the
// live one-way probe hits when the winning leg is the silent side.
func TestDissectEmitsNothingWhenEmpty(t *testing.T) {
	emitted := make(chan *api.OutputChannelItem, 4)
	stream := &mockStream{origin: api.Pcap}
	reader := &mockReader{
		tcpID:  &api.TcpID{SrcIP: "10.244.0.46", DstIP: "10.244.0.45", SrcPort: "50001", DstPort: "8899"},
		parent: stream,
		matcher: &rawMatcher{
			openMessagesMap: &sync.Map{},
		},
	}
	reader.isClient = true
	reader.emitter = &api.Emitting{AppStats: &api.AppStats{}, OutputChannel: emitted}

	d := NewDissector()
	if err := d.Dissect(bufio.NewReader(reader), reader, &api.TrafficFilteringOptions{IgnoredUserAgents: []string{}}); err != nil {
		t.Fatalf("Dissect returned error: %v", err)
	}
	select {
	case item := <-emitted:
		t.Fatalf("empty stream emitted an entry: %+v", item.Protocol)
	case <-time.After(200 * time.Millisecond):
	}
}

type mockStream struct {
	protocol *api.Protocol
	origin   api.Capture
}

func (s *mockStream) SetProtocol(p *api.Protocol)                        { s.protocol = p }
func (s *mockStream) GetOrigin() api.Capture                             { return s.origin }
func (s *mockStream) GetReqResMatchers() []api.RequestResponseMatcher    { return nil }
func (s *mockStream) GetIsTapTarget() bool                               { return true }
func (s *mockStream) GetIsClosed() bool                                  { return false }

type mockReader struct {
	data      []byte
	tcpID     *api.TcpID
	parent    api.TcpStream
	isClient  bool
	progress  *api.ReadProgress
	matcher   *rawMatcher
	counter   *api.CounterPair
	emitter   api.Emitter
	captured  time.Time
}

func (r *mockReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func (r *mockReader) GetReqResMatcher() api.RequestResponseMatcher { return r.matcher }
func (r *mockReader) GetIsClient() bool                           { return r.isClient }
func (r *mockReader) GetReadProgress() *api.ReadProgress          { return r.progress }
func (r *mockReader) GetParent() api.TcpStream                    { return r.parent }
func (r *mockReader) GetTcpID() *api.TcpID                        { return r.tcpID }
func (r *mockReader) GetCounterPair() *api.CounterPair            { return r.counter }
func (r *mockReader) GetCaptureTime() time.Time                   { return r.captured }
func (r *mockReader) GetEmitter() api.Emitter                     { return r.emitter }
func (r *mockReader) GetIsClosed() bool                           { return false }

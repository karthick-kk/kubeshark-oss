package rawtcp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/karthick-kk/kubeshark-oss/tap/api"
)

func TestPrintableSample(t *testing.T) {
	// printable bytes pass through, non-ASCII becomes '.'
	got := printableSample([]byte{0x41, 0x42, 0x00, 0x16, 0x03, 0x7f, 0xff})
	want := "AB....."
	if got != want {
		t.Fatalf("printableSample = %q, want %q", got, want)
	}
	if got := printableSample(nil); got != "" {
		t.Fatalf("printableSample(nil) = %q, want empty", got)
	}
}

// TestAnalyzeAfterJSONRoundTrip mirrors the tapper->API websocket path, which
// marshals the OutputChannelItem (payload is a map) and unmarshals it on the
// other side, turning the payload back into map[string]interface{}. This is
// exactly the shape Analyze/Summarize must handle — the same contract redis
// and http dissectors rely on.
func TestAnalyzeAfterJSONRoundTrip(t *testing.T) {
	first := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	last := first.Add(120 * time.Millisecond)

	item := &api.OutputChannelItem{
		Protocol:  protocol,
		Timestamp: first.UnixNano() / int64(time.Millisecond),
		Capture:   api.Pcap,
		Pair: &api.RequestResponsePair{
			Request: api.GenericMessage{
				IsRequest:   true,
				CaptureTime: first,
				CaptureSize: 4096,
				Payload: map[string]interface{}{
					"type":       "rawtcp",
					"bytes":      4096,
					"sample":     "GET / HTTP/1.1",
					"durationMs": int64(120),
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
	item.ConnectionInfo = &api.ConnectionInfo{
		ClientIP:   "10.244.0.187",
		ClientPort: "45678",
		ServerIP:   "10.244.0.200",
		ServerPort: "8443",
		IsOutgoing: false,
	}

	// Simulate the websocket JSON round-trip.
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round api.OutputChannelItem
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	d := NewDissector()
	entry := d.Analyze(&round, "my-agent", "keycloak", "sec-iam")

	if entry == nil {
		t.Fatal("Analyze returned nil")
	}
	if entry.Protocol.Name != "tcp" {
		t.Fatalf("protocol = %q, want tcp", entry.Protocol.Name)
	}
	if entry.Namespace != "sec-iam" {
		t.Fatalf("namespace = %q, want sec-iam", entry.Namespace)
	}
	if entry.Source.IP != "10.244.0.187" || entry.Destination.IP != "10.244.0.200" {
		t.Fatalf("5-tuple wrong: %+v -> %+v", entry.Source, entry.Destination)
	}
	if entry.Source.Name != "my-agent" || entry.Destination.Name != "keycloak" {
		t.Fatalf("resolved names wrong: %q -> %q", entry.Source.Name, entry.Destination.Name)
	}
	// durationMs is float64 after the JSON round-trip; Analyze must accept it.
	if entry.ElapsedTime != 120 {
		t.Fatalf("elapsedTime = %d, want 120", entry.ElapsedTime)
	}
	if entry.RequestSize != 4096 {
		t.Fatalf("requestSize = %d, want 4096", entry.RequestSize)
	}

	base := d.Summarize(entry)
	if base == nil {
		t.Fatal("Summarize returned nil")
	}
	if base.Summary != "GET / HTTP/1.1" {
		t.Fatalf("summary = %q, want the sample", base.Summary)
	}
	if base.Latency != 120 {
		t.Fatalf("latency = %d, want 120", base.Latency)
	}
	if base.Source == nil || base.Destination == nil {
		t.Fatal("base src/dst nil")
	}

	rep, err := d.Represent(entry.Request, entry.Response)
	if err != nil {
		t.Fatalf("Represent: %v", err)
	}
	assertSectionShape(t, string(rep))
}

// assertSectionShape pins the Represent contract the stock UI depends on:
// representation must parse to {request, response} where BOTH are arrays of
// SectionData (the UI calls .entries() on them — a plain object throws there
// and blanks the whole page).
func assertSectionShape(t *testing.T, rep string) {
	t.Helper()
	var repMap map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rep), &repMap); err != nil {
		t.Fatalf("representation not an object: %v", err)
	}
	for _, key := range []string{"request", "response"} {
		var secs []api.SectionData
		if err := json.Unmarshal(repMap[key], &secs); err != nil {
			t.Fatalf("%s is not a SectionData array (UI would call .entries() on an object and crash): %v; raw: %s", key, err, string(repMap[key]))
		}
		for i, s := range secs {
			if s.Type != api.TABLE && s.Type != api.BODY {
				t.Fatalf("%s[%d].type = %q, want table|body", key, i, s.Type)
			}
		}
	}
}

// TestMacros ensures the basenine macro so `protocol == "tcp"` filters work.
func TestMacros(t *testing.T) {
	m := NewDissector().Macros()
	if m[`tcp`] != `protocol.name == "tcp"` {
		t.Fatalf("macro = %q", m[`tcp`])
	}
}

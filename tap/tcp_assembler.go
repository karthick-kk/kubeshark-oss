package tap

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/hashicorp/golang-lru/simplelru"
	"github.com/karthick-kk/kubeshark-oss/logger"
	"github.com/karthick-kk/kubeshark-oss/tap/api"
	"github.com/karthick-kk/kubeshark-oss/tap/dbgctl"
	"github.com/karthick-kk/kubeshark-oss/tap/diagnose"
	"github.com/karthick-kk/kubeshark-oss/tap/source"
)

const (
	lastClosedConnectionsMaxItems = 1000
	packetsSeenLogThreshold       = 1000
	lastAckThreshold              = time.Duration(3) * time.Second
)

type connectionId string

func NewConnectionId(c string) connectionId {
	return connectionId(c)
}

type AssemblerStats struct {
	flushedConnections int
	closedConnections  int
}

type tcpAssembler struct {
	*reassembly.Assembler
	streamPool    *reassembly.StreamPool
	streamFactory *tcpStreamFactory
	ignoredPorts  []uint16
	// lastClosedConnections (a simplelru.LRU) and liveConnections are read by
	// the packet-processing goroutine on every packet and written both by that
	// goroutine (stream created/closed) and by the CloseTimedoutTcpStreamChannels
	// goroutine (which closes stale streams). simplelru's internal map is not
	// thread-safe, so all access goes through connectionsLock.
	lastClosedConnections  *simplelru.LRU // Actual type is map[string]int64 which is "connId -> lastSeen"
	liveConnections        map[connectionId]bool
	connectionsLock        sync.RWMutex
	maxLiveStreams         int
	staleConnectionTimeout time.Duration
	stats                  AssemblerStats
}

// Context
// The assembler context
type context struct {
	CaptureInfo gopacket.CaptureInfo
	Origin      api.Capture
}

func (c *context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

func NewTcpAssembler(outputItems chan *api.OutputChannelItem, streamsMap api.TcpStreamMap, opts *TapOpts) (*tcpAssembler, error) {
	var emitter api.Emitter = &api.Emitting{
		AppStats:      &diagnose.AppStats,
		OutputChannel: outputItems,
	}

	lastClosedConnections, err := simplelru.NewLRU(lastClosedConnectionsMaxItems, func(key interface{}, value interface{}) {})

	if err != nil {
		return nil, err
	}

	a := &tcpAssembler{
		ignoredPorts:           opts.IgnoredPorts,
		lastClosedConnections:  lastClosedConnections,
		liveConnections:        make(map[connectionId]bool),
		maxLiveStreams:         opts.maxLiveStreams,
		staleConnectionTimeout: opts.staleConnectionTimeout,
		stats:                  AssemblerStats{},
	}

	a.streamFactory = NewTcpStreamFactory(emitter, streamsMap, opts, a)
	a.streamPool = reassembly.NewStreamPool(a.streamFactory)
	a.Assembler = reassembly.NewAssembler(a.streamPool)

	maxBufferedPagesTotal := GetMaxBufferedPagesPerConnection()
	maxBufferedPagesPerConnection := GetMaxBufferedPagesTotal()
	logger.Log.Infof("Assembler options: maxBufferedPagesTotal=%d, maxBufferedPagesPerConnection=%d, opts=%+v",
		maxBufferedPagesTotal, maxBufferedPagesPerConnection, opts)
	a.Assembler.AssemblerOptions.MaxBufferedPagesTotal = maxBufferedPagesTotal
	a.Assembler.AssemblerOptions.MaxBufferedPagesPerConnection = maxBufferedPagesPerConnection

	return a, nil
}

func (a *tcpAssembler) processPackets(dumpPacket bool, packets <-chan source.TcpPacketInfo) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	ticker := time.NewTicker(a.staleConnectionTimeout)

out:
	for {
		select {
		case packetInfo, ok := <-packets:
			if !ok {
				break out
			}
			if a.processPacket(packetInfo, dumpPacket) {
				break out
			}
		case <-signalChan:
			logger.Log.Infof("Caught SIGINT: aborting")
			break out
		case <-ticker.C:
			a.periodicClean()
		}
	}

	closed := a.FlushAll()
	logger.Log.Debugf("Final flush: %d closed", closed)
}

func (a *tcpAssembler) processPacket(packetInfo source.TcpPacketInfo, dumpPacket bool) bool {
	packetsCount := diagnose.AppStats.IncPacketsCount()

	if packetsCount%packetsSeenLogThreshold == 0 {
		logger.Log.Debugf("Packets seen: #%d", packetsCount)
	}

	packet := packetInfo.Packet
	data := packet.Data()
	diagnose.AppStats.UpdateProcessedBytes(uint64(len(data)))
	if dumpPacket {
		logger.Log.Debugf("Packet content (%d/0x%x) - %s", len(data), len(data), hex.Dump(data))
	}

	tcp := packet.Layer(layers.LayerTypeTCP)
	if tcp != nil {
		a.processTcpPacket(packetInfo.Source.Origin, packet, tcp.(*layers.TCP))
	}

	done := *maxcount > 0 && int64(diagnose.AppStats.PacketsCount) >= *maxcount
	if done {
		errorMapLen, _ := diagnose.TapErrors.GetErrorsSummary()
		logger.Log.Infof("Processed %v packets (%v bytes) in %v (errors: %v, errTypes:%v)",
			diagnose.AppStats.PacketsCount,
			diagnose.AppStats.ProcessedBytes,
			time.Since(diagnose.AppStats.StartTime),
			diagnose.TapErrors.ErrorsCount,
			errorMapLen)
	}
	return done
}

func (a *tcpAssembler) processTcpPacket(origin api.Capture, packet gopacket.Packet, tcp *layers.TCP) {
	diagnose.AppStats.IncTcpPacketsCount()
	if a.shouldIgnorePort(uint16(tcp.DstPort)) || a.shouldIgnorePort(uint16(tcp.SrcPort)) {
		diagnose.AppStats.IncIgnoredPacketsCount()
		return
	}

	id := getConnectionId(packet.NetworkLayer().NetworkFlow().Src().String(),
		packet.TransportLayer().TransportFlow().Src().String(),
		packet.NetworkLayer().NetworkFlow().Dst().String(),
		packet.TransportLayer().TransportFlow().Dst().String())

	if a.isRecentlyClosed(id) {
		diagnose.AppStats.IncIgnoredLastAckCount()
		return
	}

	if a.shouldThrottle(id) {
		diagnose.AppStats.IncThrottledPackets()
		return
	}

	c := context{
		CaptureInfo: packet.Metadata().CaptureInfo,
		Origin:      origin,
	}
	diagnose.InternalStats.Totalsz += len(tcp.Payload)
	if !dbgctl.KubesharkTapperDisableTcpReassembly {
		a.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
	}
}

// Only tap-target streams are tracked in liveConnections. NewTcpStream fires
// tcpStreamCreated for EVERY flow reassembly observes, but non-tap-target
// streams never get closed (they are not stored in the streams map, so the
// timeout closer and ReassemblyComplete never run close() for them). Tracking
// them leaked the map past maxLiveStreams on high-churn clusters, after which
// shouldThrottle dropped all new connections and no entries were produced
// until a tapper restart. Tap-target streams are always cleaned up (timeout
// closer / ReassemblyComplete), so scoping the map to them keeps it bounded
// and makes the throttle reflect the streams that actually cost goroutines.
func (a *tcpAssembler) tcpStreamCreated(stream *tcpStream) {
	if !stream.isTapTarget {
		return
	}
	a.connectionsLock.Lock()
	a.liveConnections[stream.connectionId] = true
	a.connectionsLock.Unlock()
}

func (a *tcpAssembler) tcpStreamClosed(stream *tcpStream) {
	if !stream.isTapTarget {
		return
	}
	a.connectionsLock.Lock()
	a.lastClosedConnections.Add(stream.connectionId, time.Now().UnixMilli())
	delete(a.liveConnections, stream.connectionId)
	a.connectionsLock.Unlock()
}

func (a *tcpAssembler) isRecentlyClosed(c connectionId) bool {
	a.connectionsLock.RLock()
	defer a.connectionsLock.RUnlock()
	if closedTimeMillis, ok := a.lastClosedConnections.Get(c); ok {
		timeSinceClosed := time.Since(time.UnixMilli(closedTimeMillis.(int64)))
		if timeSinceClosed < lastAckThreshold {
			return true
		}
	}
	return false
}

func (a *tcpAssembler) shouldThrottle(c connectionId) bool {
	a.connectionsLock.RLock()
	defer a.connectionsLock.RUnlock()
	if _, ok := a.liveConnections[c]; ok {
		return false
	}

	return len(a.liveConnections) > a.maxLiveStreams
}

func (a *tcpAssembler) dumpStreamPool() {
	a.streamPool.Dump()
}

func (a *tcpAssembler) waitAndDump() {
	a.streamFactory.WaitGoRoutines()
	logger.Log.Debugf("%s", a.Dump())
}

func (a *tcpAssembler) shouldIgnorePort(port uint16) bool {
	for _, p := range a.ignoredPorts {
		if port == p {
			return true
		}
	}

	return false
}

func (a *tcpAssembler) periodicClean() {
	flushed, closed := a.FlushCloseOlderThan(time.Now().Add(-a.staleConnectionTimeout))
	stats := a.stats
	stats.closedConnections += closed
	stats.flushedConnections += flushed
}

func (a *tcpAssembler) DumpStats() AssemblerStats {
	result := a.stats
	a.stats = AssemblerStats{}
	return result
}

func getConnectionId(saddr string, sport string, daddr string, dport string) connectionId {
	s := fmt.Sprintf("%s:%s", saddr, sport)
	d := fmt.Sprintf("%s:%s", daddr, dport)
	if s > d {
		return NewConnectionId(fmt.Sprintf("%s#%s", s, d))
	} else {
		return NewConnectionId(fmt.Sprintf("%s#%s", d, s))
	}
}

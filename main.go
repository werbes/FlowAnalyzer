package main

/*
FlowAnalyzer - Minimal bootstrap implementation

Purpose:
- Start a small HTTP service to ingest and search network flow sessions (e.g., from MikroTik routers).
- Provide a basic web UI, health endpoint, and JSON APIs.

Assumptions added (clarifying the original notes):
- Configuration: listen address via env ADDR (default 0.0.0.0) and port via env PORT (default 8080).
- Data model: FlowSession includes timestamp, router, src/dst IP & port, protocol, bytes, packets, and optional notes.
- Storage: in-memory, thread-safe store for early development (non-persistent; resets on restart).
- Ingest format: JSON object or array of objects with RFC3339 timestamp (if omitted or invalid, current time is used).
- Query API: filter by router, src, dst, protocol, ports, time window; limit results.
- Graceful shutdown: handles Ctrl+C / termination to shut down server cleanly.
- The application can recieve Traffic Flow version 1, 5, 9 and IPFIX

Endpoints (initial version):
- GET  /              -> Minimal HTML UI with quick usage help.
- GET  /healthz       -> Health check {"status":"ok"}.
- POST /ingest        -> Ingest one or many FlowSession JSON documents.
- GET  /api/sessions  -> Query sessions via query parameters.

Planned future enhancements (based on original notes):
- Top views of bandwidth by session/protocol, anomaly detection (DoS/connection errors), latency insights, network layout graph.
- Persistent storage (e.g., SQLite/Postgres), authentication, richer UI.
*/

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	cmap "github.com/orcaman/concurrent-map/v2"
)

type FlowSession struct {
	Timestamp      time.Time `json:"timestamp"`
	Start          time.Time `json:"start,omitempty"`
	End            time.Time `json:"end,omitempty"`
	Router         string    `json:"router"`
	Routers        string    `json:"routers,omitempty"`
	SrcIP          string    `json:"src_ip"`
	SrcPort        int       `json:"src_port"`
	DstIP          string    `json:"dst_ip"`
	DstPort        int       `json:"dst_port"`
	Protocol       string    `json:"protocol"`
	Bytes          int64     `json:"bytes"`
	Packets        int64     `json:"packets"`
	PostPackets    int64     `json:"post_packets,omitempty"`
	DroppedPackets int64     `json:"dropped_packets,omitempty"`
	InIf           int       `json:"in_if,omitempty"`
	OutIf          int       `json:"out_if,omitempty"`
	SrcCountry     string    `json:"src_country,omitempty"`
	DstCountry     string    `json:"dst_country,omitempty"`
	// Optional cumulative counters and end reason (if exporter provides them)
	CumBytes   int64  `json:"cum_bytes,omitempty"`
	CumPackets int64  `json:"cum_packets,omitempty"`
	EndReason  int    `json:"end_reason,omitempty"`
	Notes      string `json:"notes,omitempty"`
	// Open session heartbeat formatting flags (not serialized)
	OpenStart bool `json:"-"`
	OpenEnd   bool `json:"-"`
}

// minuteAcc accumulates bytes and packets in a time bucket
type minuteAcc struct {
	Bytes   int64
	Packets int64
}

// ipSeries holds per-minute tx/rx for an IP (24h retention)
type ipSeries struct {
	Tx map[int64]minuteAcc
	Rx map[int64]minuteAcc
}

type Store struct {
	mu       sync.RWMutex
	sessions []FlowSession

	// Opportunistic compaction gate
	compacting int32

	// Concurrent maps storing indexed data for fast IP/protocol views
	srcMap         cmap.ConcurrentMap[string, map[string][]FlowSession] // SrcIP -> (DstIP -> recent sessions), pruned to retentionMinutes
	ipMinuteTx     cmap.ConcurrentMap[string, minuteAcc]                // "IP|unixMinute" -> tx bytes/packets
	ipMinuteRx     cmap.ConcurrentMap[string, minuteAcc]                // "IP|unixMinute" -> rx bytes/packets
	protoMinute    cmap.ConcurrentMap[string, minuteAcc]                // "PROTO|unixMinute" -> totals
	ipProtoTx      cmap.ConcurrentMap[string, minuteAcc]                // "IP|PROTO|unixMinute" -> tx
	ipProtoRx      cmap.ConcurrentMap[string, minuteAcc]                // "IP|PROTO|unixMinute" -> rx
	pairMinute     cmap.ConcurrentMap[string, minuteAcc]                // "SRC|DST|unixMinute" combined bytes/packets
	pairMinuteSess cmap.ConcurrentMap[string, int64]                    // "SRC|DST|unixMinute" -> session count

	// Per-flow state for delta tracking and start/end management
	flowStates cmap.ConcurrentMap[string, flowTrack]

	// Cross-router dedup: normalized 5-tuple signature -> owner router and last-seen time
	dedupOwners cmap.ConcurrentMap[string, sigOwner]
}

// sigOwner tracks which router currently owns a flow signature and when it was last seen
type sigOwner struct {
	Router   string
	LastSeen time.Time
	Routers  []string
}

func appendUniqueRouter(list []string, r string) []string {
	r = strings.TrimSpace(r)
	if r == "" {
		return list
	}
	for _, x := range list {
		if strings.EqualFold(x, r) {
			return list
		}
	}
	return append(list, r)
}

// flowTrack keeps state for a long-lived flow to compute deltas and proper start/end times
// It is keyed by flowKey (router, src/dst, ports, protocol, in/out iface)
// Start is the first Export Timestamp when this flow key was first seen.
// LastExport is the last Export Timestamp processed for this key.
// LastCum* are last seen cumulative counters; -1 means unknown/not provided.
// When exporter sends deltas (octetDeltaCount), we pass Bytes as-is and leave LastCum* at -1.
// When exporter sends totals (octetTotalCount), we compute delta = max(0, cur - LastCum).
// End is considered final when EndReason > 0 (if provided). We then remove the state.
// States are pruned after inactivity > retentionMinutes.

type flowTrack struct {
	Start          time.Time
	LastExport     time.Time
	LastCumBytes   int64
	LastCumPkts    int64
	LastHourLogged time.Time
	Emitted        bool
	SumBytes       int64
	SumPkts        int64
}

// tsdbWriter asynchronously writes compact flow records to a Windows-friendly time-series folder layout.
// It is enabled by default (set TSDB_ENABLE=0 to disable) so flows persist without extra configuration.
type tsdbWriter struct {
	enabled    bool
	root       string
	shards     int
	queues     []chan tsdbItem
	flushEvery time.Duration
	idleClose  time.Duration
	logDrops   bool
	logErrors  bool
	accepted   uint64 // atomic
	dropped    uint64 // atomic
	// Optional IP prefix filter: if empty, log all IPv4; if set, log only when src/dst IP is within any CIDR
	filterCIDRs []*net.IPNet
}

type tsdbItem struct {
	path string
	line []byte
}

type fileEntry struct {
	f        *os.File
	w        *bufio.Writer
	lastUsed time.Time
}

func newTSDB(root string, shards int, queueSize int, flushEvery time.Duration, idleClose time.Duration, logDrops, logErrors bool) *tsdbWriter {
	if shards <= 0 {
		shards = 1
	}
	if queueSize < shards*1024 {
		queueSize = shards * 1024
	}
	t := &tsdbWriter{
		enabled:    true,
		root:       root,
		shards:     shards,
		flushEvery: flushEvery,
		idleClose:  idleClose,
		logDrops:   logDrops,
		logErrors:  logErrors,
	}
	t.queues = make([]chan tsdbItem, shards)
	szPer := queueSize / shards
	if szPer < 1024 {
		szPer = 1024
	}
	for i := 0; i < shards; i++ {
		t.queues[i] = make(chan tsdbItem, szPer)
	}
	return t
}

func (t *tsdbWriter) Start(ctx context.Context) {
	for i := 0; i < t.shards; i++ {
		ch := t.queues[i]
		go t.runWorker(ctx, i, ch)
	}
	if t.logDrops {
		go func() {
			tick := time.NewTicker(5 * time.Second)
			defer tick.Stop()
			var lastA, lastD uint64
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					a := atomic.LoadUint64(&t.accepted)
					d := atomic.LoadUint64(&t.dropped)
					if a != lastA || d != lastD {
						log.Printf("TSDB: accepted=%d dropped=%d", a, d)
						lastA, lastD = a, d
					}
				}
			}
		}()
	}
}

func (t *tsdbWriter) runWorker(ctx context.Context, id int, in <-chan tsdbItem) {
	files := make(map[string]*fileEntry)
	flushTicker := time.NewTicker(t.flushEvery)
	defer flushTicker.Stop()
	defer func() {
		// On exit, flush and close all
		for p, fe := range files {
			_ = fe.w.Flush()
			_ = fe.f.Close()
			delete(files, p)
		}
	}()
	lastMaint := time.Now()
	doMaintenance := func() {
		now := time.Now()
		curHour := time.Now().UTC().Truncate(time.Hour)
		for p, fe := range files {
			_ = fe.w.Flush()
			// Prefer fast-close for rotated (previous-hour) files to avoid Windows locks on moved/archived files
			shouldClose := false
			if rel, err := filepath.Rel(t.root, p); err == nil {
				parts := strings.Split(rel, string(os.PathSeparator))
				if len(parts) >= 4 {
					y, errY := strconv.Atoi(parts[0])
					m, errM := strconv.Atoi(parts[1])
					d, errD := strconv.Atoi(parts[2])
					hh, errH := strconv.Atoi(parts[3])
					if errY == nil && errM == nil && errD == nil && errH == nil {
						folderTime := time.Date(y, time.Month(m), d, hh, 0, 0, 0, time.UTC)
						if folderTime.Before(curHour) && now.Sub(fe.lastUsed) >= 2*time.Second {
							shouldClose = true
						}
					}
				}
			}
			if !shouldClose {
				shouldClose = now.Sub(fe.lastUsed) >= t.idleClose
			}
			if shouldClose {
				_ = fe.f.Close()
				delete(files, p)
			}
		}
		lastMaint = now
	}
	for {
		select {
		case <-ctx.Done():
			return
		case it, ok := <-in:
			if !ok {
				return
			}
			// ensure dir
			dir := filepath.Dir(it.path)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				if t.logErrors {
					log.Printf("TSDB mkdir error: %s: %v", dir, err)
				}
				// skip this item if we cannot create the directory
				continue
			}
			// get file
			fe := files[it.path]
			if fe == nil {
				f, err := os.OpenFile(it.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
				if err != nil {
					if t.logErrors {
						log.Printf("TSDB open error: %s: %v", it.path, err)
					}
					continue
				}
				fe = &fileEntry{f: f, w: bufio.NewWriterSize(f, 64*1024), lastUsed: time.Now()}
				files[it.path] = fe
			}
			if _, err := fe.w.Write(it.line); err != nil {
				if t.logErrors {
					log.Printf("TSDB write error: %s: %v", it.path, err)
				}
				// try reopen next time by dropping handle
				_ = fe.w.Flush()
				_ = fe.f.Close()
				delete(files, it.path)
				continue
			}
			fe.lastUsed = time.Now()
			atomic.AddUint64(&t.accepted, 1)
			// Opportunistic maintenance to avoid ticker starvation under load
			if time.Since(lastMaint) >= t.flushEvery {
				doMaintenance()
			}
		case <-flushTicker.C:
			doMaintenance()
		}
	}
}

func (t *tsdbWriter) shardFor(path string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(path))
	return int(h.Sum32() % uint32(t.shards))
}

// ipAllowed returns true if the provided IPv4 is within any of the configured filter CIDRs,
// or if no filter CIDRs are configured.
func (t *tsdbWriter) ipAllowed(ip net.IP) bool {
	if t == nil {
		return false
	}
	if len(t.filterCIDRs) == 0 {
		return true
	}
	for _, n := range t.filterCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (t *tsdbWriter) EnqueueMany(sessions []FlowSession) {
	if t == nil || !t.enabled {
		return
	}
	for i := range sessions {
		s := sessions[i]
		// Skip zero-byte/zero-packet non-final entries, but allow zero-byte finals (End set)
		if s.Bytes <= 0 && s.Packets <= 0 && s.End.IsZero() {
			continue
		}
		// src
		if p, line, ok := t.buildPathAndLine(true, s); ok {
			sh := t.shardFor(p)
			select {
			case t.queues[sh] <- tsdbItem{path: p, line: line}:
			default:
				atomic.AddUint64(&t.dropped, 1)
			}
		}
		// dst
		if p, line, ok := t.buildPathAndLine(false, s); ok {
			sh := t.shardFor(p)
			select {
			case t.queues[sh] <- tsdbItem{path: p, line: line}:
			default:
				atomic.AddUint64(&t.dropped, 1)
			}
		}
	}
}

func twoDigit(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func (t *tsdbWriter) buildPathAndLine(isSrc bool, s FlowSession) (string, []byte, bool) {
	ipStr := s.DstIP
	name := "dst-port.log"
	if isSrc {
		ipStr = s.SrcIP
		name = "src-port.log"
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", nil, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return "", nil, false
	}
	// Optional CIDR filter per side: only log if this side's IP is allowed (or no filter configured)
	if len(t.filterCIDRs) > 0 && !t.ipAllowed(v4) {
		return "", nil, false
	}
	// choose time (UTC) for folder and line
	start := s.Start
	if start.IsZero() {
		start = s.Timestamp
	}
	end := s.End
	if end.IsZero() {
		end = s.Timestamp
	}
	st := start.UTC()
	et := end.UTC()
	// Folder hour: for open-ended (ongoing) entries, use the export/timestamp hour; otherwise use start hour
	folderTime := st
	if s.OpenEnd {
		folderTime = s.Timestamp.UTC()
	}
	y := strconv.Itoa(folderTime.Year())
	m := twoDigit(int(folderTime.Month()))
	d := twoDigit(folderTime.Day())
	hh := twoDigit(folderTime.Hour())
	p := filepath.Join(t.root, y, m, d, hh,
		strconv.Itoa(int(v4[0])), strconv.Itoa(int(v4[1])), strconv.Itoa(int(v4[2])), strconv.Itoa(int(v4[3])), name)
	// Build start/end strings (placeholders when requested)
	startStr := fmt.Sprintf("%02d:%02d:%02d", st.Hour(), st.Minute(), st.Second())
	if s.OpenStart {
		startStr = "--:--:--"
	}
	endStr := fmt.Sprintf("%02d:%02d:%02d", et.Hour(), et.Minute(), et.Second())
	if s.OpenEnd {
		endStr = "--:--:--"
	}
	// Enhanced line: "HH:MM:SS HH:MM:SS bytes packets proto srcIP:srcPort > dstIP:dstPort router=R\n"
	// Router field enhancement: if s.Routers is populated, prefer it; otherwise try to look up
	// historical routers from dedupOwners; fallback to s.Router.
	routerVal := strings.TrimSpace(s.Router)
	if strings.TrimSpace(s.Routers) != "" {
		routerVal = strings.TrimSpace(s.Routers)
	} else if dedupEnable {
		if owner, ok := store.dedupOwners.Get(flowSig(s)); ok {
			if len(owner.Routers) > 0 {
				routerVal = strings.Join(owner.Routers, ",")
			}
		}
	}
	line := []byte(fmt.Sprintf("%s %s %d %d %s %s:%d > %s:%d router=%s\n",
		startStr, endStr, s.Bytes, s.Packets,
		strings.ToUpper(strings.TrimSpace(s.Protocol)), strings.TrimSpace(s.SrcIP), s.SrcPort, strings.TrimSpace(s.DstIP), s.DstPort, routerVal))
	return p, line, true
}

func NewStore() *Store {
	s := &Store{}
	s.srcMap = cmap.New[map[string][]FlowSession]()
	s.ipMinuteTx = cmap.New[minuteAcc]()
	s.ipMinuteRx = cmap.New[minuteAcc]()
	s.protoMinute = cmap.New[minuteAcc]()
	s.ipProtoTx = cmap.New[minuteAcc]()
	s.ipProtoRx = cmap.New[minuteAcc]()
	s.pairMinute = cmap.New[minuteAcc]()
	s.pairMinuteSess = cmap.New[int64]()
	s.flowStates = cmap.New[flowTrack]()
	s.dedupOwners = cmap.New[sigOwner]()
	return s
}

// internal configuration (populated in main)
var (
	retentionMinutes                = 5
	flowTimeoutMinutes              = 2
	aggregateOlderThanMinutes       = 0
	aggregateBucketSeconds          = 60
	compactEverySeconds             = 30
	maxSessionsBeforeCompactTrigger = 50000

	// Metrics summaries retention (hours) for ip/proto/pair minute maps
	summariesRetentionHours = 8

	// UDP collector concurrency controls (bounded)
	collectorWorkers = runtime.GOMAXPROCS(0) * 2
	collectorQueue   = 8192

	// Max concurrent WebSocket log feed connections
	wsMaxConns = 200

	// Cross-router dedup configuration
	dedupEnable = true
	dedupTTL    = 1 * time.Minute
)

func (s *Store) AddMany(items []FlowSession) int {
	accepted := items
	if dedupEnable {
		accepted = s.applyDedup(items)
		if len(accepted) == 0 {
			return 0
		}
	}
	// Apply flow tracking to compute deltas and proper Start/End handling, plus open-session heartbeats
	tracked, opens := s.applyFlowTracking(accepted)
	if len(tracked) == 0 && len(opens) == 0 {
		return 0
	}
	// Append tracked (non-heartbeat) to primary slice under lock
	shouldCompact := false
	s.mu.Lock()
	if len(tracked) > 0 {
		s.sessions = append(s.sessions, tracked...)
		// Opportunistic compact trigger based on size threshold (gated)
		if len(s.sessions) > maxSessionsBeforeCompactTrigger {
			shouldCompact = true
		}
	}
	s.mu.Unlock()
	// Fire compact outside the lock and gate to a single goroutine
	if shouldCompact && atomic.CompareAndSwapInt32(&s.compacting, 0, 1) {
		go func() {
			defer atomic.StoreInt32(&s.compacting, 0)
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Compact panic: %v", r)
				}
			}()
			s.Compact()
			s.pruneSummaries()
		}()
	}
	// Update concurrent indices and summaries without holding the store lock
	if len(tracked) > 0 {
		s.indexAndSummarize(tracked)
	}
	// Persist to TSDB: write all tracked items (non-final with data are allowed by EnqueueMany) and open heartbeats
	if tsdb != nil {
		if len(tracked) > 0 {
			tsdb.EnqueueMany(tracked)
		}
		if len(opens) > 0 {
			tsdb.EnqueueOpenMany(opens)
		}
	}
	// Broadcast to WS listeners (non-blocking) only tracked items (not heartbeats)
	for _, s := range tracked {
		select {
		case newSessionsChan <- s:
		default:
		}
		// If this record finalized the session, also notify end for live removal
		if !s.End.IsZero() && !s.OpenEnd {
			select {
			case endedSessionsChan <- s:
			default:
			}
		}
	}
	return len(tracked)
}

// applyDedup filters a batch to keep only sessions owned by a single router per 5-tuple within a TTL.
// Additionally, it records the set of routers observed for the flow signature and populates FlowSession.Routers
// for accepted sessions so consumers can see the historical path across routers/ISPs.
func (s *Store) applyDedup(items []FlowSession) []FlowSession {
	now := time.Now()
	acc := make([]FlowSession, 0, len(items))
	for _, fs := range items {
		if strings.TrimSpace(fs.Router) == "" {
			// If router is unknown, we cannot deduplicate reliably; accept it
			acc = append(acc, fs)
			continue
		}
		sig := flowSig(fs)
		allowed := false
		s.dedupOwners.Upsert(sig, sigOwner{Router: fs.Router, LastSeen: now, Routers: []string{fs.Router}}, func(exist bool, cur, newVal sigOwner) sigOwner {
			if !exist || now.Sub(cur.LastSeen) > dedupTTL {
				// No owner or expired -> claim ownership for this router and reset history
				allowed = true
				return sigOwner{Router: fs.Router, LastSeen: now, Routers: []string{fs.Router}}
			}
			// Always record this router in history
			cur.Routers = appendUniqueRouter(cur.Routers, fs.Router)
			if cur.Router == fs.Router {
				// Same owner -> accept and refresh last seen
				allowed = true
				cur.LastSeen = now
				return cur
			}
			// Different router owns and not expired -> drop (keep history; do NOT refresh last seen to allow ownership to expire)
			allowed = false
			return cur
		})
		if allowed {
			// Populate historical routers string (comma-separated) for visibility
			if owner, ok := s.dedupOwners.Get(sig); ok {
				if len(owner.Routers) > 0 {
					fs.Routers = strings.Join(owner.Routers, ",")
				} else {
					fs.Routers = fs.Router
				}
			} else {
				fs.Routers = fs.Router
			}
			acc = append(acc, fs)
		}
	}
	return acc
}

// applyFlowTracking computes deltas for ongoing sessions and manages Start/End
func (s *Store) applyFlowTracking(items []FlowSession) ([]FlowSession, []FlowSession) {
	if len(items) == 0 {
		return items, nil
	}
	out := make([]FlowSession, 0, len(items))
	opens := make([]FlowSession, 0)
	for _, in := range items {
		k := flowKey(in)
		exportTs := in.Timestamp
		st, ok := s.flowStates.Get(k)
		if !ok {
			st = flowTrack{Start: exportTs, LastExport: exportTs, LastCumBytes: -1, LastCumPkts: -1}
		}
		// Determine deltas
		var dB, dP int64
		if in.CumBytes > 0 {
			if st.LastCumBytes >= 0 {
				dB = in.CumBytes - st.LastCumBytes
			} else {
				dB = 0
			}
			st.LastCumBytes = in.CumBytes
		} else {
			dB = in.Bytes
		}
		if in.CumPackets > 0 {
			if st.LastCumPkts >= 0 {
				dP = in.CumPackets - st.LastCumPkts
			} else {
				dP = 0
			}
			st.LastCumPkts = in.CumPackets
		} else {
			dP = in.Packets
		}
		if dB < 0 {
			dB = 0
		}
		if dP < 0 {
			dP = 0
		}
		// accumulate running sums for delta-only flows
		st.SumBytes += dB
		st.SumPkts += dP
		st.LastExport = exportTs

		// Determine finalization: explicit reason or End provided
		final := in.EndReason != 0 || (!in.End.IsZero())
		outSess := in
		outSess.Bytes = dB
		outSess.Packets = dP
		// Ensure Start is the earliest between input Start (if any) and tracked Start
		if !in.Start.IsZero() && (st.Start.IsZero() || in.Start.Before(st.Start)) {
			st.Start = in.Start
		}
		outSess.Start = st.Start

		// Heartbeat/open entry once per hour: only for flows that started before this hour
		curHour := exportTs.UTC().Truncate(time.Hour)
		if (st.LastHourLogged.IsZero() || !st.LastHourLogged.UTC().Equal(curHour)) && st.Start.Before(curHour) {
			open := outSess
			open.OpenEnd = true
			open.OpenStart = true
			open.Bytes = 0
			open.Packets = 0
			open.Timestamp = exportTs
			opens = append(opens, open)
			st.LastHourLogged = curHour
		}

		// If final but we haven't emitted any data and only have cumulative totals, use totals
		if final && dB == 0 && dP == 0 && !st.Emitted {
			if in.CumBytes > 0 {
				outSess.Bytes = in.CumBytes
			}
			if in.CumPackets > 0 {
				outSess.Packets = in.CumPackets
			}
		}

		// Write back state (unless finalized below)
		s.flowStates.Set(k, st)

		if final {
			// Final: End should be export timestamp if not provided
			if outSess.End.IsZero() {
				outSess.End = exportTs
			}
			// Remove state upon finalization
			s.flowStates.Remove(k)
		}
		// Only append when there is any accounting to add or when finalizing (to ensure TSDB has start/end)
		if dB > 0 || dP > 0 || final {
			// mark emitted if we actually carry data
			if outSess.Bytes > 0 || outSess.Packets > 0 {
				st.Emitted = true
				// persist updated Emitted if not final (if final, state removed anyway)
				if !final {
					s.flowStates.Set(k, st)
				}
			}
			out = append(out, outSess)
		}
	}
	return out, opens
}

// Compact applies retention policy and optional aggregation to reduce memory usage.
func (s *Store) Compact() {
	now := time.Now()
	retentionCutoff := now.Add(-time.Duration(retentionMinutes) * time.Minute)
	aggregateCutoff := now.Add(-time.Duration(aggregateOlderThanMinutes) * time.Minute)
	bucket := time.Duration(aggregateBucketSeconds) * time.Second

	// Short-circuit if retention is zero or negative (keep all)
	if retentionMinutes <= 0 {
		return
	}

	type aggKey struct {
		Router, SrcIP, DstIP, Protocol, SrcCountry, DstCountry string
		SrcPort, DstPort, InIf, OutIf                          int
		BucketUnix                                             int64
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// In-place filtering to avoid allocating a new large slice (reduces runtime.duffcopy)
	writeIdx := 0
	// Aggregate older entries into time buckets using pointers to minimize value copying
	agg := make(map[aggKey]*FlowSession)
	for i := 0; i < len(s.sessions); i++ {
		sess := s.sessions[i]
		eff := effectiveEndOrTs(sess)
		if eff.Before(retentionCutoff) {
			// drop
			continue
		}
		if aggregateOlderThanMinutes > 0 && !eff.After(aggregateCutoff) {
			// aggregate into time bucket
			bts := eff.Truncate(bucket).Unix()
			k := aggKey{
				Router: sess.Router, SrcIP: sess.SrcIP, DstIP: sess.DstIP, Protocol: sess.Protocol,
				SrcCountry: sess.SrcCountry, DstCountry: sess.DstCountry,
				SrcPort: sess.SrcPort, DstPort: sess.DstPort, InIf: sess.InIf, OutIf: sess.OutIf,
				BucketUnix: bts,
			}
			if cur := agg[k]; cur != nil {
				cur.Bytes += sess.Bytes
				cur.Packets += sess.Packets
				cur.PostPackets += sess.PostPackets
				cur.DroppedPackets += sess.DroppedPackets
			} else {
				bucketStart := time.Unix(bts, 0).UTC()
				nsess := FlowSession{
					Timestamp:      bucketStart,
					Start:          bucketStart,
					End:            bucketStart.Add(bucket),
					Router:         sess.Router,
					SrcIP:          sess.SrcIP,
					SrcPort:        sess.SrcPort,
					DstIP:          sess.DstIP,
					DstPort:        sess.DstPort,
					Protocol:       sess.Protocol,
					Bytes:          sess.Bytes,
					Packets:        sess.Packets,
					PostPackets:    sess.PostPackets,
					DroppedPackets: sess.DroppedPackets,
					InIf:           sess.InIf,
					OutIf:          sess.OutIf,
					SrcCountry:     sess.SrcCountry,
					DstCountry:     sess.DstCountry,
				}
				agg[k] = &nsess
			}
			continue
		}
		// keep recent: write in place
		s.sessions[writeIdx] = sess
		writeIdx++
	}

	// Trim to the kept recent items
	s.sessions = s.sessions[:writeIdx]

	// Append aggregated items (usually capacity is sufficient, so no reallocation/copy)
	if len(agg) > 0 {
		for _, v := range agg {
			s.sessions = append(s.sessions, *v)
		}
	}

	// Sort chronologically (ascending) by effective end or timestamp, in place
	sort.Slice(s.sessions, func(i, j int) bool { return effectiveEndOrTs(s.sessions[i]).Before(effectiveEndOrTs(s.sessions[j])) })
}

// StartMaintenance starts background routines: compaction/summaries and hourly open-session emits.
func (s *Store) StartMaintenance(ctx context.Context) {
	// Compaction ticker (optional)
	if compactEverySeconds > 0 {
		ticker := time.NewTicker(time.Duration(compactEverySeconds) * time.Second)
		go func() {
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					s.Compact()
					s.pruneSummaries()
				}
			}
		}()
	}
	// Hourly open-session heartbeat emitter: ensures ongoing sessions appear in each hour's logs
	go func() {
		// Tick every 15s; act only when hour changes
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		var lastHour time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				curHour := time.Now().UTC().Truncate(time.Hour)
				if lastHour.Equal(curHour) {
					continue
				}
				lastHour = curHour
				if tsdb == nil {
					continue
				}
				// Build open entries for all active flow states that were not logged for this hour yet
				opens := make([]FlowSession, 0, 1024)
				for k, st := range s.flowStates.Items() {
					if !st.LastHourLogged.IsZero() && st.LastHourLogged.UTC().Equal(curHour) {
						continue
					}
					// Only emit open heartbeat for flows that started before this hour
					if !st.Start.Before(curHour) {
						continue
					}
					fs, ok := flowSessionFromKey(k, st)
					if !ok {
						continue
					}
					fs.OpenEnd = true
					fs.OpenStart = true
					fs.Bytes = 0
					fs.Packets = 0
					fs.Timestamp = time.Now()
					fs.Start = st.Start
					opens = append(opens, fs)
					// Update state to avoid duplicates from both tick and ingestion
					st.LastHourLogged = curHour
					s.flowStates.Set(k, st)
				}
				if len(opens) > 0 {
					tsdb.EnqueueOpenMany(opens)
				}
			}
		}
	}()

	// Idle-timeout sweeper: finalize and remove inactive flow states so live sessions don't get stuck
	go func() {
		// Sweep every 30 seconds
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				// If timeout disabled or non-positive, skip
				if flowTimeoutMinutes <= 0 {
					continue
				}
				cutoff := time.Now().Add(-time.Duration(flowTimeoutMinutes) * time.Minute)
				for k, st := range s.flowStates.Items() {
					if st.LastExport.Before(cutoff) {
						fs, ok := flowSessionFromKey(k, st)
						// Remove state first to avoid double handling
						s.flowStates.Remove(k)
						if !ok {
							continue
						}
						// Build a minimal final session for UI removal
						fs.Timestamp = st.LastExport
						fs.Start = st.Start
						fs.End = st.LastExport
						// Prefer historical router path if available
						sig := flowSig(fs)
						if owner, ok := s.dedupOwners.Get(sig); ok {
							if len(owner.Routers) > 0 {
								fs.Routers = strings.Join(owner.Routers, ",")
							}
						}
						select {
						case endedSessionsChan <- fs:
						default:
						}
					}
				}
			}
		}
	}()
}

type Query struct {
	Router   string
	SrcIP    string
	DstIP    string
	Protocol string
	SrcPort  int
	DstPort  int
	Since    time.Time
	Until    time.Time
	Limit    int
}

func (s *Store) Filter(q Query) []FlowSession {
	// Iterate under read lock without copying the entire slice to reduce memory spikes
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []FlowSession
	// Iterate from the end to return most recent first
	var prev time.Time
	prevSet := false
	monotonic := true // track if effective end/timestamps are non-increasing as we scan backwards
	for i := len(s.sessions) - 1; i >= 0; i-- {
		sess := s.sessions[i]
		eff := effectiveEndOrTs(sess)
		if prevSet {
			if eff.After(prev) { // order violation
				monotonic = false
			} else {
				prev = eff
			}
		} else {
			prev = eff
			prevSet = true
		}
		// Early exit when scanning older entries if we have a lower bound and ordering is monotonic
		if monotonic && !q.Since.IsZero() && eff.Before(q.Since) {
			break
		}

		if q.Router != "" && !strings.EqualFold(sess.Router, q.Router) {
			continue
		}
		if q.SrcIP != "" && !strings.Contains(sess.SrcIP, q.SrcIP) {
			continue
		}
		if q.DstIP != "" && !strings.Contains(sess.DstIP, q.DstIP) {
			continue
		}
		if q.Protocol != "" && !strings.EqualFold(sess.Protocol, q.Protocol) {
			continue
		}
		if q.SrcPort != 0 && sess.SrcPort != q.SrcPort {
			continue
		}
		if q.DstPort != 0 && sess.DstPort != q.DstPort {
			continue
		}
		// Time window filtering: prefer interval overlap if Start/End provided; fallback to Timestamp
		if !q.Since.IsZero() || !q.Until.IsZero() {
			start := sess.Start
			end := sess.End
			if start.IsZero() && end.IsZero() {
				// Instant record at Timestamp
				if !q.Since.IsZero() && sess.Timestamp.Before(q.Since) {
					continue
				}
				if !q.Until.IsZero() && sess.Timestamp.After(q.Until) {
					continue
				}
			} else {
				if start.IsZero() {
					start = sess.Timestamp
				}
				if end.IsZero() {
					end = sess.Timestamp
				}
				if end.Before(start) {
					start, end = end, start
				}
				// Overlap check between [start, end] and [since, until]
				if !q.Since.IsZero() && end.Before(q.Since) {
					continue
				}
				if !q.Until.IsZero() && start.After(q.Until) {
					continue
				}
			}
		}
		out = append(out, sess)
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	if out == nil {
		return []FlowSession{}
	}
	return out
}

var store = NewStore()

// tsdb is the asynchronous filesystem time-series writer (initialized in main)
var tsdb *tsdbWriter

// Global CIDR filter for UI/API filtering independent of TSDB being enabled.
var uiFilterCIDRs []*net.IPNet

// newSessionsChan carries newly accepted sessions for optional live WebSocket feeds.
var newSessionsChan = make(chan FlowSession, 1024)

// WebSocket live feed state
var wsUpgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

// endedSessionsChan carries sessions that have completed, so live views can remove them.
var endedSessionsChan = make(chan FlowSession, 1024)

type wsFilter struct {
	IP      string
	Side    string // both|src|dst
	Src     string
	Dst     string
	Proto   string
	Port    int
	SrcPort int
	DstPort int
}

// Connections for /ws/logs (log tail)
var wsMu sync.RWMutex
var wsConns = make(map[*websocket.Conn]wsFilter)

// Connections for /ws/sessions (live sessions)
var wsSessMu sync.RWMutex
var wsSessConns = make(map[*websocket.Conn]wsFilter)

type wsSessRow struct {
	Start    string `json:"start"`
	Last     string `json:"last"`
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`
	SrcPort  int    `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
	Bytes    int64  `json:"bytes"`
	Packets  int64  `json:"packets"`
	Router   string `json:"router"`
}

type wsSessEvent struct {
	Event   string    `json:"event"` // add|end
	Key     string    `json:"key"`
	Session wsSessRow `json:"session,omitempty"`
}

func wsStart(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case s := <-newSessionsChan:
				// Snapshot clients under lock for logs feed
				wsMu.RLock()
				targets := make([]struct {
					Conn   *websocket.Conn
					Filter wsFilter
				}, 0, len(wsConns))
				for c, f := range wsConns {
					targets = append(targets, struct {
						Conn   *websocket.Conn
						Filter wsFilter
					}{Conn: c, Filter: f})
				}
				wsMu.RUnlock()

				// Prepare item for matches and write
				var toRemove []*websocket.Conn
				for _, t := range targets {
					if !wsMatches(t.Filter, s) {
						continue
					}
					item := fsLogItemFromSession(t.Filter.IP, s)
					_ = t.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if err := t.Conn.WriteJSON(item); err != nil {
						toRemove = append(toRemove, t.Conn)
					}
				}
				if len(toRemove) > 0 {
					wsMu.Lock()
					for _, c := range toRemove {
						_ = c.Close()
						delete(wsConns, c)
					}
					wsMu.Unlock()
				}

				// Broadcast to live sessions clients as an 'add' event (update/create)
				wsSessMu.RLock()
				sTargets := make([]struct {
					Conn   *websocket.Conn
					Filter wsFilter
				}, 0, len(wsSessConns))
				for c, f := range wsSessConns {
					sTargets = append(sTargets, struct {
						Conn   *websocket.Conn
						Filter wsFilter
					}{Conn: c, Filter: f})
				}
				wsSessMu.RUnlock()
				var sessToRemove []*websocket.Conn
				for _, t := range sTargets {
					if !wsMatches(t.Filter, s) {
						continue
					}
					row := wsSessRow{
						Start: func() string {
							st := s.Start
							if st.IsZero() {
								st = s.Timestamp
							}
							return st.UTC().Format(time.RFC3339)
						}(),
						Last:     s.Timestamp.UTC().Format(time.RFC3339),
						Protocol: strings.ToUpper(s.Protocol),
						SrcIP:    s.SrcIP,
						SrcPort:  s.SrcPort,
						DstIP:    s.DstIP,
						DstPort:  s.DstPort,
						Bytes: func() int64 {
							if s.Bytes < 0 {
								return 0
							}
							return s.Bytes
						}(),
						Packets: func() int64 {
							if s.Packets < 0 {
								return 0
							}
							return s.Packets
						}(),
						Router: func() string {
							if strings.TrimSpace(s.Routers) != "" {
								return s.Routers
							}
							return s.Router
						}(),
					}
					// Skip zero-total sessions to avoid cluttering the live view
					if row.Bytes <= 0 && row.Packets <= 0 {
						continue
					}
					ev := wsSessEvent{Event: "add", Key: wsSessKey(s), Session: row}
					_ = t.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if err := t.Conn.WriteJSON(ev); err != nil {
						sessToRemove = append(sessToRemove, t.Conn)
					}
				}
				if len(sessToRemove) > 0 {
					wsSessMu.Lock()
					for _, c := range sessToRemove {
						_ = c.Close()
						delete(wsSessConns, c)
					}
					wsSessMu.Unlock()
				}
			case s := <-endedSessionsChan:
				// Broadcast 'end' event to live sessions clients so they can remove rows
				wsSessMu.RLock()
				sTargets := make([]struct {
					Conn   *websocket.Conn
					Filter wsFilter
				}, 0, len(wsSessConns))
				for c, f := range wsSessConns {
					sTargets = append(sTargets, struct {
						Conn   *websocket.Conn
						Filter wsFilter
					}{Conn: c, Filter: f})
				}
				wsSessMu.RUnlock()
				var sessToRemove2 []*websocket.Conn
				for _, t := range sTargets {
					if !wsMatches(t.Filter, s) {
						continue
					}
					ev := wsSessEvent{Event: "end", Key: wsSessKey(s)}
					_ = t.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if err := t.Conn.WriteJSON(ev); err != nil {
						sessToRemove2 = append(sessToRemove2, t.Conn)
					}
				}
				if len(sessToRemove2) > 0 {
					wsSessMu.Lock()
					for _, c := range sessToRemove2 {
						_ = c.Close()
						delete(wsSessConns, c)
					}
					wsSessMu.Unlock()
				}
			}
		}
	}()
}

func wsMatches(f wsFilter, s FlowSession) bool {
	// IP relevance and side
	if f.IP != "" {
		has := s.SrcIP == f.IP || s.DstIP == f.IP
		if !has {
			return false
		}
		if f.Side == "src" && s.SrcIP != f.IP {
			return false
		}
		if f.Side == "dst" && s.DstIP != f.IP {
			return false
		}
	}
	if f.Src != "" && !strings.Contains(s.SrcIP, f.Src) {
		return false
	}
	if f.Dst != "" && !strings.Contains(s.DstIP, f.Dst) {
		return false
	}
	if f.Proto != "" && !strings.EqualFold(s.Protocol, f.Proto) {
		return false
	}
	if f.Port > 0 && !(s.SrcPort == f.Port || s.DstPort == f.Port) {
		return false
	}
	if f.SrcPort > 0 && s.SrcPort != f.SrcPort {
		return false
	}
	if f.DstPort > 0 && s.DstPort != f.DstPort {
		return false
	}
	return true
}

func fsLogItemFromSession(ip string, s FlowSession) fsLogItem {
	start := s.Start
	end := s.End
	if start.IsZero() {
		start = s.Timestamp
	}
	if end.IsZero() {
		end = s.Timestamp
	}
	side := ""
	if ip != "" {
		if s.SrcIP == ip {
			side = "src"
		} else if s.DstIP == ip {
			side = "dst"
		}
	}
	// Prefer Routers (historical path) if present; fallback to single Router for compatibility
	rval := s.Router
	if strings.TrimSpace(s.Routers) != "" {
		rval = s.Routers
	}
	return fsLogItem{
		Start:    start.UTC().Format(time.RFC3339),
		End:      end.UTC().Format(time.RFC3339),
		Bytes:    s.Bytes,
		Packets:  s.Packets,
		Protocol: strings.ToUpper(s.Protocol),
		SrcIP:    s.SrcIP,
		SrcPort:  s.SrcPort,
		DstIP:    s.DstIP,
		DstPort:  s.DstPort,
		Router:   rval,
		Side:     side,
	}
}

func main() {
	// If running as a Windows Service, let the service code take over (no-op on non-Windows)
	if maybeRunService() {
		return
	}
	addr := getenv("ADDR", "0.0.0.0")
	port := getenv("PORT", "8080")
	listen := fmt.Sprintf("%s:%s", addr, port)

	// Configure memory/aggregation knobs from environment with sensible defaults
	if n, err := strconv.Atoi(getenv("RETENTION_MINUTES", fmt.Sprintf("%d", retentionMinutes))); err == nil {
		retentionMinutes = n
	}
	if n, err := strconv.Atoi(getenv("FLOW_TIMEOUT_MINUTES", fmt.Sprintf("%d", flowTimeoutMinutes))); err == nil {
		flowTimeoutMinutes = n
	}
	if n, err := strconv.Atoi(getenv("COMPACT_EVERY_SECONDS", fmt.Sprintf("%d", compactEverySeconds))); err == nil {
		compactEverySeconds = n
	}
	if n, err := strconv.Atoi(getenv("MAX_SESSIONS_TRIGGER", fmt.Sprintf("%d", maxSessionsBeforeCompactTrigger))); err == nil {
		maxSessionsBeforeCompactTrigger = n
	}
	// New safeguards tunables
	if n, err := strconv.Atoi(getenv("METRICS_RETENTION_HOURS", fmt.Sprintf("%d", summariesRetentionHours))); err == nil {
		summariesRetentionHours = n
	}
	if n, err := strconv.Atoi(getenv("COLLECTOR_WORKERS", fmt.Sprintf("%d", collectorWorkers))); err == nil {
		collectorWorkers = n
	}
	if n, err := strconv.Atoi(getenv("COLLECTOR_QUEUE", fmt.Sprintf("%d", collectorQueue))); err == nil {
		collectorQueue = n
	}
	if n, err := strconv.Atoi(getenv("WS_MAX_CONNS", fmt.Sprintf("%d", wsMaxConns))); err == nil {
		wsMaxConns = n
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/ingest", ingestHandler)
	mux.HandleFunc("/api/sessions", sessionsHandler)
	mux.HandleFunc("/api/metrics/throughput", throughputHandler)
	mux.HandleFunc("/api/metrics/top", topHandler)
	mux.HandleFunc("/api/metrics/throughput_by_protocol_precomputed", throughputByProtocolPrecomputedHandler)
	// Log search API
	mux.HandleFunc("/api/logs/search", logsSearchHandler)
	// New IP-centric APIs
	mux.HandleFunc("/api/top_ips", topIPsHandler)
	mux.HandleFunc("/api/ip/protocols", ipProtocolsHandler)
	mux.HandleFunc("/api/ip/peers", ipPeersHandler)
	mux.HandleFunc("/api/ips", ipsHandler)
	mux.HandleFunc("/api/ip", ipViewHandler)
	mux.HandleFunc("/api/ip_table", ipTableHandler)
	// Bad IPs (no-response attempts)
	mux.HandleFunc("/api/bad-ips", badIPsAPIHandler)
	// New UI page for dedicated log search window
	mux.HandleFunc("/logs", logsPageHandler)
	// New UI page for live sessions view
	mux.HandleFunc("/live", liveSessionsPageHandler)
	// UI page for bad IPs
	mux.HandleFunc("/bad-ips", badIPsPageHandler)
	// WebSocket endpoints for live feeds
	mux.HandleFunc("/ws/logs", wsLogsHandler)
	mux.HandleFunc("/ws/sessions", wsSessionsHandler)
	mux.HandleFunc("/", ipTableIndexHandler)

	// Optional pprof endpoints
	if getenvBool("PPROF_ENABLE", false) {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	var handler http.Handler = mux
	// enable gzip compression for supported clients
	handler = gzipMiddleware(handler)
	if getenvBool("LOG_REQUESTS", false) {
		handler = logRequests(handler)
	}

	srv := &http.Server{Addr: listen, Handler: handler}

	// Context for background collectors
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	// Start background store maintenance
	store.StartMaintenance(bgCtx)
	// Start WebSocket broadcaster
	wsStart(bgCtx)

	// Configure cross-router dedup from environment
	dedupEnable = getenvBool("DEDUP_ENABLE", true)
	ttlMin := getenvInt("DEDUP_TTL_MIN", 1)
	if ttlMin <= 0 {
		ttlMin = 1
	}
	dedupTTL = time.Duration(ttlMin) * time.Minute
	log.Printf("Dedup: enabled=%v ttl=%s", dedupEnable, dedupTTL.String())

	// Initialize filesystem TSDB (enabled by default). Set TSDB_ENABLE=0 to disable.
	if getenvBool("TSDB_ENABLE", true) {
		root := getenv("TSDB_ROOT", "E:\\DB")
		// Ensure root exists; if creation fails (e.g., no E: drive), fall back to .\DB
		if err := os.MkdirAll(root, 0o755); err != nil {
			fb := ".\\DB"
			if getenvBool("TSDB_LOG_ERRORS", true) {
				log.Printf("TSDB: cannot use root %s (%v), falling back to %s", root, err, fb)
			}
			root = fb
			_ = os.MkdirAll(root, 0o755)
		}
		shards := getenvInt("TSDB_SHARDS", runtime.GOMAXPROCS(0))
		qsize := getenvInt("TSDB_QUEUE_SIZE", 65536)
		flushMs := getenvInt("TSDB_FLUSH_MS", 1000)
		idleSec := getenvInt("TSDB_IDLE_CLOSE_SEC", 60)
		logDrops := getenvBool("TSDB_LOG_DROPS", false)
		logErrors := getenvBool("TSDB_LOG_ERRORS", true)
		tsdb = newTSDB(root, shards, qsize, time.Duration(flushMs)*time.Millisecond, time.Duration(idleSec)*time.Second, logDrops, logErrors)
		// Optional filter by CIDR prefixes for src/dst addresses written to filesystem
		if cidrs := getenv("TSDB_FILTER_CIDRS", ""); cidrs != "" {
			nets := parseCIDRList(cidrs)
			tsdb.filterCIDRs = nets
			log.Printf("TSDB filter: %d CIDRs active", len(nets))
		}
		tsdb.Start(bgCtx)
		log.Printf("TSDB enabled: root=%s shards=%d queue=%d", root, shards, qsize)
	}

	// Always initialize UI filter from env regardless of TSDB_ENABLE
	if cidrs := getenv("TSDB_FILTER_CIDRS", ""); cidrs != "" {
		uiFilterCIDRs = parseCIDRList(cidrs)
		log.Printf("UI filter: %d CIDRs active", len(uiFilterCIDRs))
	}

	// Preload country database so ingestion goroutines never trigger loading
	ensureCountryDB()

	// Start UDP collectors (NetFlow v1/v5/v9 and IPFIX)
	startFlowCollectors(bgCtx)

	// Start HTTP server
	go func() {
		log.Printf("FlowAnalyzer listening on http://%s", listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	// stop background collectors
	bgCancel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	log.Printf("Shutting down...")
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	} else {
		log.Printf("Server stopped")
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func ingestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var batch []FlowSession
	// Try array first
	if err := json.Unmarshal(body, &batch); err != nil {
		// Try single object
		var one FlowSession
		if err2 := json.Unmarshal(body, &one); err2 != nil {
			http.Error(w, "invalid JSON payload", http.StatusBadRequest)
			return
		}
		batch = []FlowSession{one}
	}

	// Normalize and validate
	now := time.Now()
	normalized := make([]FlowSession, 0, len(batch))
	for _, s := range batch {
		if s.Timestamp.IsZero() {
			s.Timestamp = now
		}
		s.Protocol = strings.ToUpper(strings.TrimSpace(s.Protocol))
		s.Router = strings.TrimSpace(s.Router)
		s.SrcIP = strings.TrimSpace(s.SrcIP)
		s.DstIP = strings.TrimSpace(s.DstIP)
		if s.Router == "" || s.SrcIP == "" || s.DstIP == "" {
			// skip invalid entry
			continue
		}
		normalized = append(normalized, s)
	}
	if len(normalized) > 0 {
		fillCountries(normalized)
	}

	n := store.AddMany(normalized)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ingested": n,
		"received": len(batch),
	})
}

func sessionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := Query{
		Router:   strings.TrimSpace(r.URL.Query().Get("router")),
		SrcIP:    strings.TrimSpace(r.URL.Query().Get("src")),
		DstIP:    strings.TrimSpace(r.URL.Query().Get("dst")),
		Protocol: strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("protocol"))),
	}
	if v := r.URL.Query().Get("src_port"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.SrcPort = n
		}
	}
	if v := r.URL.Query().Get("dst_port"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.DstPort = n
		}
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, ok := parseTime(v); ok {
			q.Since = t
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if t, ok := parseTime(v); ok {
			q.Until = t
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			q.Limit = n
		}
	}

	res := store.Filter(q)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// throughputHandler returns time-bucketed throughput metrics.
func throughputHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	router := strings.TrimSpace(r.URL.Query().Get("router"))
	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")
	stepSec := 60
	if v := r.URL.Query().Get("step"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			stepSec = n
		}
	}
	var since, until time.Time
	if sinceStr != "" {
		if t, ok := parseTime(sinceStr); ok {
			since = t
		}
	}
	if untilStr != "" {
		if t, ok := parseTime(untilStr); ok {
			until = t
		}
	}
	now := time.Now()
	if until.IsZero() {
		until = now
	}
	if since.IsZero() {
		since = until.Add(-1 * time.Hour)
	}
	step := time.Duration(stepSec) * time.Second
	startAligned := since.Truncate(step)

	q := Query{Router: router, Since: since, Until: until}
	res := store.Filter(q)
	// Sort records by effective end time to allow per-flow interval inference
	sort.Slice(res, func(i, j int) bool { return effectiveEndOrTs(res[i]).Before(effectiveEndOrTs(res[j])) })
	prevEnd := make(map[string]time.Time)

	// Aggregate into buckets with interval-aware distribution
	type acc struct {
		Bytes   int64
		Packets int64
	}
	bins := make(map[int64]acc)
	var totalBytes int64
	var totalPackets int64

	for _, s := range res {
		if s.Bytes <= 0 && s.Packets <= 0 {
			continue
		}
		// Determine interval for this record, inferring Start when missing
		start := s.Start
		end := s.End
		if end.IsZero() {
			end = s.Timestamp
		}
		if start.IsZero() {
			key := flowKey(s)
			if pe, ok := prevEnd[key]; ok && pe.Before(end) {
				start = pe
			} else {
				start = end.Add(-step)
			}
		}
		if end.Before(start) {
			start, end = end, start
		}

		// Intersect with requested window
		if end.Before(since) || start.After(until) {
			prevEnd[flowKey(s)] = end
			continue
		}
		if start.Before(since) {
			start = since
		}
		if end.After(until) {
			end = until
		}

		dur := end.Sub(start)
		if dur <= 0 {
			// Fallback: assign to the record's bucket
			b := s.Timestamp.Truncate(step).Unix()
			a := bins[b]
			a.Bytes += s.Bytes
			a.Packets += s.Packets
			bins[b] = a
			totalBytes += s.Bytes
			totalPackets += s.Packets
			prevEnd[flowKey(s)] = end
			continue
		}

		// Distribute proportionally across overlapping buckets
		firstBucket := start.Truncate(step)
		lastBucket := end.Truncate(step)
		var assignedBytes int64
		var assignedPackets int64
		for t := firstBucket; !t.After(lastBucket); t = t.Add(step) {
			bucketStart := t
			bucketEnd := t.Add(step)
			// Overlap with [start, end)
			overlapStart := start
			if bucketStart.After(overlapStart) {
				overlapStart = bucketStart
			}
			overlapEnd := end
			if bucketEnd.Before(overlapEnd) {
				overlapEnd = bucketEnd
			}
			o := overlapEnd.Sub(overlapStart)
			if o <= 0 {
				continue
			}
			frac := float64(o) / float64(dur)
			bPart := int64(math.Round(frac * float64(s.Bytes)))
			pPart := int64(math.Round(frac * float64(s.Packets)))
			// Fix rounding on the last bucket to conserve totals
			if t.Equal(lastBucket) {
				bPart = s.Bytes - assignedBytes
				pPart = s.Packets - assignedPackets
			}
			k := t.Unix()
			a := bins[k]
			a.Bytes += bPart
			a.Packets += pPart
			bins[k] = a
			assignedBytes += bPart
			assignedPackets += pPart
		}
		totalBytes += s.Bytes
		totalPackets += s.Packets
		prevEnd[flowKey(s)] = end
	}

	points := make([]map[string]any, 0)
	for t := startAligned; !t.After(until); t = t.Add(step) {
		k := t.Unix()
		a := bins[k]
		bps := float64(a.Bytes*8) / float64(stepSec)
		points = append(points, map[string]any{
			"ts":      t.UTC().Format(time.RFC3339),
			"bytes":   a.Bytes,
			"packets": a.Packets,
			"bps":     bps,
		})
	}

	payload := map[string]any{
		"router":        router,
		"since":         startAligned.UTC().Format(time.RFC3339),
		"until":         until.UTC().Format(time.RFC3339),
		"step":          stepSec,
		"total_bytes":   totalBytes,
		"total_packets": totalPackets,
		"points":        points,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// topHandler returns top-N aggregates by a chosen dimension (src/dst ip/port, country).
func topHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	by := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("by")))
	if by == "" {
		http.Error(w, "missing 'by' parameter", http.StatusBadRequest)
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	router := strings.TrimSpace(r.URL.Query().Get("router"))
	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")
	var since, until time.Time
	if sinceStr != "" {
		if t, ok := parseTime(sinceStr); ok {
			since = t
		}
	}
	if untilStr != "" {
		if t, ok := parseTime(untilStr); ok {
			until = t
		}
	}
	now := time.Now()
	if until.IsZero() {
		until = now
	}
	if since.IsZero() {
		since = until.Add(-1 * time.Hour)
	}

	q := Query{Router: router, Since: since, Until: until}
	rows := store.Filter(q)

	type agg struct {
		Bytes   int64
		Packets int64
		Flows   int64
	}
	acc := make(map[string]*agg)
	var totalBytes int64
	var totalPackets int64
	var totalFlows int64

	getKey := func(s FlowSession) (string, bool) {
		switch by {
		case "src_ip":
			return s.SrcIP, true
		case "dst_ip":
			return s.DstIP, true
		case "src_port":
			return strconv.Itoa(s.SrcPort), true
		case "dst_port":
			return strconv.Itoa(s.DstPort), true
		case "src_country":
			k := s.SrcCountry
			if strings.TrimSpace(k) == "" {
				k = "Unknown"
			}
			return k, true
		case "dst_country":
			k := s.DstCountry
			if strings.TrimSpace(k) == "" {
				k = "Unknown"
			}
			return k, true
		default:
			return "", false
		}
	}

	for _, s := range rows {
		k, ok := getKey(s)
		if !ok || k == "" {
			continue
		}
		if acc[k] == nil {
			acc[k] = &agg{}
		}
		a := acc[k]
		a.Bytes += s.Bytes
		a.Packets += s.Packets
		a.Flows += 1
		totalBytes += s.Bytes
		totalPackets += s.Packets
		totalFlows += 1
	}

	type item struct {
		Key     string `json:"key"`
		Bytes   int64  `json:"bytes"`
		Packets int64  `json:"packets"`
		Flows   int64  `json:"flows"`
	}
	items := make([]item, 0, len(acc))
	for k, a := range acc {
		items = append(items, item{Key: k, Bytes: a.Bytes, Packets: a.Packets, Flows: a.Flows})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Bytes > items[j].Bytes })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}

	payload := map[string]any{
		"by":            by,
		"router":        router,
		"since":         since.UTC().Format(time.RFC3339),
		"until":         until.UTC().Format(time.RFC3339),
		"limit":         limit,
		"total_bytes":   totalBytes,
		"total_packets": totalPackets,
		"total_flows":   totalFlows,
		"items":         items,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// CountryDB: download and cache ipverse/rir-ip zip for at least 1 day; parse aggregated IPv4 ranges per country

type ipRange struct {
	start uint32
	end   uint32
	cc    string
}

type countryDBState struct {
	mu         sync.RWMutex
	ranges     []ipRange
	loadedAt   time.Time
	lastErr    error
	lastErrLog time.Time
	loading    bool
	cond       *sync.Cond
}

var countryDB countryDBState

const rirZipURL = "https://codeload.github.com/ipverse/rir-ip/zip/refs/heads/master"

func ensureCountryDB() {
	// Fast path: already loaded
	countryDB.mu.RLock()
	if len(countryDB.ranges) > 0 {
		countryDB.mu.RUnlock()
		return
	}
	countryDB.mu.RUnlock()

	// Single-flight load to avoid multiple concurrent downloads/parses
	countryDB.mu.Lock()
	if countryDB.cond == nil {
		countryDB.cond = sync.NewCond(&countryDB.mu)
	}
	// Re-check under lock
	if len(countryDB.ranges) > 0 {
		countryDB.mu.Unlock()
		return
	}
	if countryDB.loading {
		for countryDB.loading && len(countryDB.ranges) == 0 {
			countryDB.cond.Wait()
		}
		countryDB.mu.Unlock()
		return
	}
	countryDB.loading = true
	countryDB.mu.Unlock()

	// Perform load outside of lock to avoid deadlocks (loadCountryDB acquires the lock)
	err := loadCountryDB()

	countryDB.mu.Lock()
	countryDB.loading = false
	if err != nil {
		countryDB.lastErr = err
		if time.Since(countryDB.lastErrLog) > time.Minute {
			log.Printf("country DB load error: %v", err)
			countryDB.lastErrLog = time.Now()
		}
	}
	if countryDB.cond != nil {
		countryDB.cond.Broadcast()
	}
	countryDB.mu.Unlock()
}

func cacheZipPath() string {
	cacheDir := filepath.Join(".", "cache")
	_ = os.MkdirAll(cacheDir, 0o755)
	return filepath.Join(cacheDir, "rir-ip-master.zip")
}

func ensureZipCached() (string, error) {
	path := cacheZipPath()
	if fi, err := os.Stat(path); err == nil {
		if time.Since(fi.ModTime()) < 24*time.Hour {
			return path, nil
		}
	}
	// download
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest(http.MethodGet, rirZipURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: %s", resp.Status)
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(f, resp.Body)
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

func loadCountryDB() error {
	zipPath, err := ensureZipCached()
	if err != nil {
		return err
	}
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	var ranges []ipRange
	for _, f := range r.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if !strings.Contains(name, "/country/") {
			continue
		}
		if !strings.HasSuffix(name, "/ipv4-aggregated.txt") {
			continue
		}
		parts := strings.Split(name, "/")
		// find index of "country"
		cc := ""
		for i := 0; i < len(parts)-1; i++ {
			if parts[i] == "country" && i+1 < len(parts) {
				cc = parts[i+1]
				break
			}
		}
		if cc == "" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		s := bufio.NewScanner(rc)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			_, ipnet, perr := net.ParseCIDR(line)
			if perr != nil || ipnet == nil {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil {
				continue
			}
			start := ipToUint32(ip)
			mask := binary.BigEndian.Uint32(ipnet.Mask)
			end := start | ^mask
			ranges = append(ranges, ipRange{start: start, end: end, cc: strings.ToUpper(cc)})
		}
		_ = rc.Close()
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	countryDB.mu.Lock()
	countryDB.ranges = ranges
	countryDB.loadedAt = time.Now()
	countryDB.mu.Unlock()
	log.Printf("country DB loaded: %d ranges", len(ranges))
	return nil
}

func ipToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

func countryForIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	ensureCountryDB()
	countryDB.mu.RLock()
	rgs := countryDB.ranges
	countryDB.mu.RUnlock()
	if len(rgs) == 0 {
		return ""
	}
	val := ipToUint32(ip)
	// binary search for range with start <= val; then check end
	i := sort.Search(len(rgs), func(i int) bool { return rgs[i].start > val || rgs[i].start == val })
	// adjust i to the last range whose start <= val
	if i < len(rgs) && rgs[i].start == val {
		if val <= rgs[i].end {
			return rgs[i].cc
		}
	}
	if i == 0 {
		return ""
	}
	i = i - 1
	if val >= rgs[i].start && val <= rgs[i].end {
		return rgs[i].cc
	}
	return ""
}

func fillCountries(sessions []FlowSession) {
	for i := range sessions {
		if sessions[i].SrcCountry == "" {
			sessions[i].SrcCountry = countryForIP(sessions[i].SrcIP)
		}
		if sessions[i].DstCountry == "" {
			sessions[i].DstCountry = countryForIP(sessions[i].DstIP)
		}
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>FlowAnalyzer Dashboard</title>
<style>
:root{--bg:#0b1020;--panel:#141a2f;--muted:#8b96b1;--accent:#4f8cff;--ok:#1fbe7a;--warn:#ffb020;--err:#ff5d5d;}
*{box-sizing:border-box}
body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:var(--bg);color:#e6edf3}
header{padding:1rem 1.5rem;border-bottom:1px solid #22283d;display:flex;gap:1rem;align-items:center;flex-wrap:wrap}
header h1{font-size:1.25rem;margin:0}
.container{padding:1rem 1.5rem}
.controls{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
select,input,button{background:#0f1529;color:#e6edf3;border:1px solid #253055;border-radius:6px;padding:.5rem .6rem}
button{cursor:pointer}
.grid{display:grid;grid-template-columns:2fr 1fr;gap:1rem}
@media(max-width:1000px){.grid{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid #22283d;border-radius:10px;padding:1rem}
.mono{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace}
small.muted{color:var(--muted)}
.table{width:99%;border-collapse:collapse}
.table th,.table td{padding:.4rem .5rem;border-bottom:1px solid #22283d;white-space:nowrap}
.table th{color:#b8c1d6;text-align:left;font-weight:600}
.kpis{display:flex;gap:1rem;flex-wrap:wrap;margin:.5rem 0 0}
.kpis .kpi{background:#0f1529;border:1px solid #22283d;border-radius:8px;padding:.5rem .75rem;min-width:130px}
.kpi .label{color:#9aa6c8;font-size:.8rem}
.kpi .value{font-size:1.1rem;font-weight:600}
.details{margin-top:.5rem}
details summary{cursor:pointer;color:#9aa6c8}
.badge{font-size:.75rem;background:#0f1529;border:1px solid #22283d;border-radius:999px;padding:.15rem .5rem}
footer{padding:1rem 1.5rem;border-top:1px solid #22283d;color:#9aa6c8}
#chart{height:36vh !important;height:36svh !important;height:36dvh !important;max-height:36vh !important;max-height:36svh !important;max-height:36dvh !important;width:95%}
.tops-grid{display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-top:.5rem}
@media(max-width:1000px){.tops-grid{grid-template-columns:1fr}}
.tops-grid canvas{height:240px !important;max-height:240px !important;width:100%}
.tops-grid h3{margin:.25rem 0 .5rem;font-size:.95rem;color:#b8c1d6}
.iface-grid{display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-top:.5rem}
@media(max-width:1000px){.iface-grid{grid-template-columns:1fr}}
.iface-grid .iface-card{background:#0f1529;border:1px solid #22283d;border-radius:8px;padding:.5rem}
.iface-grid canvas{height:160px !important;max-height:160px !important;width:100%}
#allRoutersSection{margin-top:1rem;display:none}
.dual-grid{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}
@media(max-width:1000px){.dual-grid{grid-template-columns:1fr}}
.dual-grid canvas{height:32vh !important;height:32svh !important;height:32dvh !important;max-height:32vh !important;max-height:32svh !important;max-height:32dvh !important;width:100%}
</style>
</head>
<body>
<header>
  <h1>FlowAnalyzer</h1>
  <div class="controls">
    <label>Router
      <select id="routerSelect">
        <option value="">All routers</option>
      </select>
    </label>
    <label>Range
      <select id="rangeSelect">
        <option value="15m">Last 15m</option>
        <option value="1h" selected>Last 1h</option>
        <option value="6h">Last 6h</option>
        <option value="24h">Last 24h</option>
      </select>
    </label>
    <button id="refreshBtn">Refresh</button>
    <small class="muted">Auto-refresh every 5s</small>
  </div>
</header>
<div class="container">
  <div class="grid">
    <section class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap">
        <h2 style="margin:.25rem 0;font-size:1rem;color:#b8c1d6">Bandwidth (bps)</h2>
        <div class="kpis">
          <div class="kpi"><div class="label">Avg bps</div><div class="value mono" id="avgBps">-</div></div>
          <div class="kpi"><div class="label">Max bps</div><div class="value mono" id="maxBps">-</div></div>
          <div class="kpi"><div class="label">Total bytes</div><div class="value mono" id="totalBytes">-</div></div>
          <div class="kpi"><div class="label">Total packets</div><div class="value mono" id="totalPkts">-</div></div>
        </div>
      </div>
      <canvas id="chart"></canvas>
      <div class="details">
        <details>
          <summary>API help</summary>
          <div class="muted" style="margin-top:.5rem">
            <div>Health: <span class="badge">GET /healthz</span></div>
            <div>Ingest: <span class="badge">POST /ingest</span></div>
            <div>Sessions: <span class="badge">GET /api/sessions</span></div>
            <div>Throughput: <span class="badge">GET /api/metrics/throughput</span></div>
            <div>Per-Interface: <span class="badge">GET /api/metrics/throughput_by_interface?router=ROUTER&since=..&until=..&step=..</span></div>
            <div>Top: <span class="badge">GET /api/metrics/top?by=src_ip|dst_ip|src_port|dst_port|src_country|dst_country</span></div>
          </div>
        </details>
      </div>
      <div id="ifaceSection" style="margin-top:1rem;display:none">
        <h2 style="margin:.25rem 0 .5rem;font-size:1rem;color:#b8c1d6">Per-interface Bandwidth</h2>
        <div id="ifaceGrid" class="iface-grid"></div>
      </div>
      <div id="allRoutersSection">
        <h2 style="margin:.25rem 0 .5rem;font-size:1rem;color:#b8c1d6">All Routers Comparison</h2>
        <div class="dual-grid">
          <div>
            <h3>Top 5 Routers by Bandwidth</h3>
            <canvas id="topRoutersBandwidth"></canvas>
            <div id="legendBandwidth" class="muted" style="margin-top:.25rem;font-size:.8rem"></div>
          </div>
          <div>
            <h3>Top 5 Routers by Packet Loss</h3>
            <canvas id="topRoutersLoss"></canvas>
            <div id="legendLoss" class="muted" style="margin-top:.25rem;font-size:.8rem"></div>
          </div>
        </div>
      </div>
      <div style="margin-top:1rem">
        <h2 style="margin:.25rem 0 .5rem;font-size:1rem;color:#b8c1d6">Top 10</h2>
        <div class="tops-grid">
          <div>
            <h3>Src IPs</h3>
            <canvas id="topSrcIPs"></canvas>
          </div>
          <div>
            <h3>Dst IPs</h3>
            <canvas id="topDstIPs"></canvas>
          </div>
          <div>
            <h3>Src Ports</h3>
            <canvas id="topSrcPorts"></canvas>
          </div>
          <div>
            <h3>Dst Ports</h3>
            <canvas id="topDstPorts"></canvas>
          </div>
          <div>
            <h3>Src Countries</h3>
            <canvas id="topSrcCountries"></canvas>
          </div>
          <div>
            <h3>Dst Countries</h3>
            <canvas id="topDstCountries"></canvas>
          </div>
        </div>
      </div>
    </section>
    <section class="card">
      <h2 style="margin:.25rem 0  .75rem;font-size:1rem;color:#b8c1d6">Current Sessions</h2>
      <table class="table mono" id="sessionsTable">
        <thead>
          <tr>
            <th>Time</th>
            <th>Router</th>
            <th>Src</th>
            <th>Dst</th>
            <th>Proto</th>
            <th>SrcPort</th>
            <th>DstPort</th>
            <th>Bytes</th>
            <th>Packets</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </section>
  </div>
</div>
<footer>
  <span id="status" class="muted">Ready</span>
</footer>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://unpkg.com/tablefilter@latest/dist/tablefilter/tablefilter.js"></script>
<script>
var $ = function(s){ return document.querySelector(s); };
var routerSelect = $("#routerSelect");
var rangeSelect = $("#rangeSelect");
var refreshBtn = $("#refreshBtn");
var statusEl = $("#status");
var chart;
var isRefreshing = false;
var lastRoutersAt = 0;
var tfInited = false;
var tfInstance = null;
function initTableFilter(){
  if(tfInited) return;
  try{
    var filtersConfig = {
      base_path: 'https://unpkg.com/tablefilter@latest/dist/tablefilter/',
      auto_filter: { delay: 300 },
      highlight_keywords: true,
      rows_counter: true,
      btn_reset: true,
      status_bar: true,
      extensions: [{ name: 'sort' }],
      col_types: ['string','string','string','string','string','number','number','number','number']
    };
    tfInstance = new TableFilter('sessionsTable', filtersConfig);
    tfInstance.init();
    tfInited = true;
  }catch(e){ console.error('TableFilter init failed', e); }
}

function fmtBytes(n){
  var u=['B','KB','MB','GB','TB'];
  var i=0, x=n;
  while(x>=1024 && i<u.length-1){x/=1024;i++}
  return (x>=100?x.toFixed(0):x>=10?x.toFixed(1):x.toFixed(2))+' '+u[i];
}
function fmtBps(n){
  var u=['bps','Kbps','Mbps','Gbps','Tbps'];
  var i=0,x=n;
  while(x>=1000 && i<u.length-1){x/=1000;i++}
  return (x>=100?x.toFixed(0):x>=10?x.toFixed(1):x.toFixed(2))+' '+u[i];
}
function rangeToMs(v){
  if(v==='15m') return 15*60*1000;
  if(v==='1h') return 60*60*1000;
  if(v==='6h') return 6*60*60*1000;
  return 24*60*60*1000;
}
function rangeToStepSec(v){
  if(v==='15m') return 5;
  if(v==='1h') return 30;
  if(v==='6h') return 120;
  return 600;
}
function computeSince(){
  var now=Date.now();
  return new Date(now - rangeToMs(rangeSelect.value));
}
async function loadRouters(){
  try{
    var since = new Date(Date.now()-24*60*60*1000).toISOString();
    var res = await fetch("/api/sessions?limit=500&since=" + encodeURIComponent(since));
    var arr = [];
    try{ arr = await res.json(); }catch(_){}
    if(!Array.isArray(arr)) arr = [];
    var set = new Set(arr.map(function(x){return x.router;}).filter(Boolean));
    var selVal = routerSelect.value;
    var optionsHtml = '<option value="">All routers</option>' + Array.from(set).sort().map(function(r){return '<option>' + r + '</option>';}).join('');
    if(routerSelect.innerHTML !== optionsHtml){
      routerSelect.innerHTML = optionsHtml;
      if(Array.from(set).indexOf(selVal) !== -1) routerSelect.value = selVal;
    }
  }catch(e){console.error(e)}
}
async function loadThroughput(){
  var since = computeSince();
  var until = new Date();
  var step = rangeToStepSec(rangeSelect.value);
  var params = new URLSearchParams({since: since.toISOString(), until: until.toISOString(), step: String(step)});
  if(routerSelect.value) params.set('router', routerSelect.value);
  var url = '/api/metrics/throughput_by_protocol?' + params.toString();
  statusEl.textContent = 'Loading throughput...';
  var res = await fetch(url);
  var data = await res.json();
  var series = data.series || [];
  // Build labels from first series
  var labels = series.length ? (series[0].points||[]).map(function(p){return new Date(p.ts).toLocaleTimeString();}) : [];
  // Prepare datasets per protocol
  var datasets = series.map(function(s, i){
    var color = palette[i%palette.length] || '#4f8cff';
    var rgba = hexToRgba(color, 0.5);
    var arr = (s.points||[]).map(function(p){ return p.bps; });
    return { label: s.protocol || 'UNK', data: arr, borderColor: color, backgroundColor: rgba, fill: true, tension: .25, pointRadius: 0, stack: 'protocols' };
  });
  // Compute KPIs from total (sum over protocols per bucket)
  var totalBps = [];
  if(labels.length){
    var len = labels.length;
    for(var i=0;i<len;i++){
      var sum = 0;
      for(var j=0;j<datasets.length;j++){
        var v = datasets[j].data[i] || 0;
        sum += v;
      }
      totalBps.push(sum);
    }
  }
  var avg = totalBps.length ? (totalBps.reduce(function(a,b){return a+b;},0)/totalBps.length) : 0;
  var max = totalBps.length ? Math.max.apply(null, totalBps) : 0;
  $("#avgBps").textContent = fmtBps(avg);
  $("#maxBps").textContent = fmtBps(max);
  $("#totalBytes").textContent = fmtBytes(data.total_bytes||0);
  $("#totalPkts").textContent = String(data.total_packets||0).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  var ctx = document.getElementById('chart');
  if(!chart){
    chart = new Chart(ctx, {
      type:'line',
      data:{ labels: labels, datasets: datasets },
      options:{
        responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ display:true }, tooltip:{ callbacks:{ label:function(c){ return c.dataset && c.dataset.label ? (c.dataset.label+': '+fmtBps(c.parsed.y)) : fmtBps(c.parsed.y); } } } },
        scales:{ x:{ grid:{ color:'#22283d' } }, y:{ stacked:true, grid:{ color:'#22283d' }, ticks:{ callback:function(v){ return fmtBps(v); } } } }
      }
    });
  }else{
    chart.data.labels = labels;
    chart.data.datasets = datasets;
    chart.options.scales.y.stacked = true;
    chart.update();
  }
  statusEl.textContent = 'Updated ' + new Date().toLocaleTimeString();
}

// Per-interface throughput charts
var ifaceCharts = {};
function clearIfaceCharts(){
  try{ Object.values(ifaceCharts).forEach(function(ch){ if(ch && ch.destroy) ch.destroy(); }); }catch(e){}
  ifaceCharts = {};
  var grid = document.getElementById('ifaceGrid'); if(grid) grid.innerHTML='';
}
async function loadIfaceThroughput(){
  var section = document.getElementById('ifaceSection');
  if(!routerSelect.value){ if(section) section.style.display='none'; clearIfaceCharts(); return; }
  var since = computeSince();
  var until = new Date();
  var step = rangeToStepSec(rangeSelect.value);
  var params = new URLSearchParams({since: since.toISOString(), until: until.toISOString(), step: String(step), router: routerSelect.value});
  var res = await fetch('/api/metrics/throughput_by_interface?' + params.toString());
  var data = await res.json();
  var series = data.series || [];
  var grid = document.getElementById('ifaceGrid');
  if(!grid || !section) return;
  if(series.length === 0){ section.style.display='none'; clearIfaceCharts(); return; }
  section.style.display = 'block';
  // Render cards
  grid.innerHTML = series.map(function(s){
    var tb = fmtBytes(s.total_bytes||0);
    var tp = (s.total_packets||0).toLocaleString();
    return '<div class="iface-card">'+
      '<div style="display:flex;justify-content:space-between;align-items:baseline">'+
      '<h3 style="margin:.25rem 0;color:#b8c1d6">Interface '+s.iface+'</h3>'+
      '<small class="muted">'+tb+' • pkts '+tp+'</small>'+
      '</div>'+
      '<canvas id="ifaceChart-'+s.iface+'"></canvas>'+
    '</div>';
  }).join('');
  // Build charts
  series.forEach(function(s){
    var id = 'ifaceChart-' + s.iface;
    var el = document.getElementById(id);
    if(!el) return;
    var labels = (s.points||[]).map(function(p){ return new Date(p.ts).toLocaleTimeString(); });
    var bps = (s.points||[]).map(function(p){ return p.bps; });
    var ctx = el.getContext('2d');
    if(ifaceCharts[id]){ try{ ifaceCharts[id].destroy(); }catch(e){} }
    ifaceCharts[id] = new Chart(ctx, {
      type:'line',
      data:{labels:labels,datasets:[{label:'bps',data:bps,borderColor:'#1fbe7a',backgroundColor:'rgba(31,190,122,0.15)',fill:true,tension:.25,pointRadius:0}]},
      options:{responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}, tooltip:{callbacks:{label:function(c){return fmtBps(c.parsed.y);}}}}, scales:{x:{grid:{color:'#22283d'}}, y:{grid:{color:'#22283d'}, ticks:{callback:function(v){return fmtBps(v);}}}}}
    });
  });
}

async function loadSessions(){
  var since = computeSince();
  var params = new URLSearchParams({limit:'100', since: since.toISOString()});
  if(routerSelect.value) params.set('router', routerSelect.value);
  var res = await fetch('/api/sessions?' + params.toString());
  var arr = [];
  try{ arr = await res.json(); }catch(_){ arr = []; }
  if(!Array.isArray(arr)) arr = [];
  var tbody = document.querySelector('#sessionsTable tbody');
  tbody.innerHTML = arr.map(function(s){
    var t = new Date(s.timestamp).toLocaleTimeString();
    var src = s.src_ip;
    var dst = s.dst_ip;
    return '<tr>'+
      '<td>'+t+'</td>'+
      '<td>'+(s.router||'')+'</td>'+
      '<td>'+src+'</td>'+
      '<td>'+dst+'</td>'+
      '<td>'+(s.protocol||'')+'</td>'+
      '<td>'+(s.src_port||'')+'</td>'+
      '<td>'+(s.dst_port||'')+'</td>'+
      '<td>'+((s.bytes||0).toLocaleString())+'</td>'+
      '<td>'+((s.packets||0).toLocaleString())+'</td>'+
    '</tr>';
  }).join('');
  initTableFilter();
  try{ if(tfInited && tfInstance && typeof tfInstance.refresh==='function'){ tfInstance.refresh(); } }catch(e){}
  try{ if(tfInited && tfInstance && typeof tfInstance.filter==='function'){ tfInstance.filter(); } }catch(e){}
}

// Top charts
var topCharts = {};
function renderTopChart(canvasId, items){
  var labels = items.map(function(it){ return it.key; });
  var values = items.map(function(it){ return it.bytes; });
  var ctx = document.getElementById(canvasId).getContext('2d');
  var ds = {label:'Bytes', data: values, backgroundColor: 'rgba(79,140,255,0.35)', borderColor: '#4f8cff'};
  var opts = {responsive:true, maintainAspectRatio:false, indexAxis:'y', plugins:{legend:{display:false}, tooltip:{callbacks:{label:function(c){ var i=c.dataIndex; var it=items[i]; return fmtBytes(it.bytes)+' • pkts '+(it.packets||0).toLocaleString()+' • flows '+(it.flows||0).toLocaleString(); }}}}, scales:{x:{grid:{color:'#22283d'}, ticks:{callback:function(v){return fmtBytes(v);}}}, y:{grid:{color:'#22283d'}}}};
  if(!topCharts[canvasId]){
    topCharts[canvasId] = new Chart(ctx, {type:'bar', data:{labels: labels, datasets:[ds]}, options: opts});
  }else{
    var ch = topCharts[canvasId];
    ch.data.labels = labels;
    ch.data.datasets[0].data = values;
    ch.update();
  }
}
function getTopLimit(){ try{ var n=parseInt(localStorage.getItem('topLimit')||'10',10); return (n>0?n:10);}catch(e){ return 10; } }
async function fetchTop(by){
  var since = computeSince();
  var until = new Date();
  var params = new URLSearchParams({since: since.toISOString(), until: until.toISOString(), limit: String(getTopLimit()), by: by});
  if(routerSelect.value) params.set('router', routerSelect.value);
  var res = await fetch('/api/metrics/top?' + params.toString());
  return res.json();
}
async function loadTops(){
  var conf = [
    ['src_ip','topSrcIPs'],
    ['dst_ip','topDstIPs'],
    ['src_port','topSrcPorts'],
    ['dst_port','topDstPorts'],
    ['src_country','topSrcCountries'],
    ['dst_country','topDstCountries']
  ];
  var promises = conf.map(function(p){ return fetchTop(p[0]).then(function(d){ return [p[1], d.items||[]]; }); });
  var results = await Promise.all(promises);
  results.forEach(function(x){ renderTopChart(x[0], x[1]); });
}

// All routers comparison charts
var topRouterBwChart=null, topRouterLossChart=null;
function destroyChart(ch){ try{ if(ch && ch.destroy) ch.destroy(); }catch(e){} }
function hexToRgba(hex, a){
  var h = hex.replace('#','');
  if(h.length===3){ h = h.split('').map(function(c){return c+c;}).join(''); }
  var r = parseInt(h.substring(0,2),16);
  var g = parseInt(h.substring(2,4),16);
  var b = parseInt(h.substring(4,6),16);
  return 'rgba('+r+','+g+','+b+','+a+')';
}
var palette = ['#4f8cff', '#1fbe7a', '#ffb020', '#ff5d5d', '#a970ff'];
function runLimited(fns, limit){
  limit = (limit|0) > 0 ? (limit|0) : 3;
  var i = 0, running = 0, results = new Array(fns.length);
  return new Promise(function(resolve){
    function pump(){
      if(i >= fns.length && running === 0){ resolve(Promise.all(results)); return; }
      while(running < limit && i < fns.length){
        (function(idx){
          var fn = fns[idx];
          running++;
          Promise.resolve().then(fn).then(function(res){
            results[idx] = res;
          }).catch(function(err){
            console.error('task error', err);
            results[idx] = null;
          }).finally(function(){ running--; pump(); });
        })(i++);
      }
    }
    pump();
  });
}
function buildLegend(el, labels, colors){
  if(!el) return;
  el.innerHTML = labels.map(function(lbl, i){
    var c = colors[i%colors.length];
    return '<span style="display:inline-flex;align-items:center;margin-right:.75rem;margin-top:.25rem">'
      + '<span style="display:inline-block;width:.75rem;height:.75rem;background:'+c+';border-radius:2px;margin-right:.35rem"></span>'
      + '<span class="mono">'+lbl+'</span>'
      + '</span>';
  }).join('');
}
async function fetchRouterSeries(url){
  var since = computeSince();
  var until = new Date();
  var step = rangeToStepSec(rangeSelect.value);
  var params = new URLSearchParams({since: since.toISOString(), until: until.toISOString(), step: String(step), limit: '5'});
  var res = await fetch(url + '?' + params.toString());
  return res.json();
}
function renderRouterSeriesChart(canvasId, legendId, data, mode){
  var series = data.series || [];
  var canvas = document.getElementById(canvasId);
  var legendEl = document.getElementById(legendId);
  if(!canvas){ return null; }
  if(series.length===0){ if(legendEl) legendEl.innerHTML=''; var ctx=canvas.getContext('2d'); try{ctx.clearRect(0,0,canvas.width,canvas.height);}catch(e){} return null; }
  var labels = (series[0].points||[]).map(function(p){ return new Date(p.ts).toLocaleTimeString(); });
  var datasets = series.map(function(s, i){
    var color = palette[i%palette.length];
    var rgba = hexToRgba(color, 0.6);
    var dataArr = (s.points||[]).map(function(p){ return mode==='bps' ? p.bps : (p.loss||0); });
    return { label: s.router, data: dataArr, borderColor: rgba, backgroundColor: 'transparent', fill:false, tension:.25, pointRadius:0 };
  });
  var ctx = canvas.getContext('2d');
  var chart = new Chart(ctx, {
    type:'line',
    data:{ labels: labels, datasets: datasets },
    options:{ responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{ display:false }, tooltip:{ callbacks:{ label:function(c){ return mode==='bps' ? fmtBps(c.parsed.y) : (c.parsed.y||0).toLocaleString()+' pkts'; } } } },
      scales:{ x:{ grid:{ color:'#22283d' } }, y:{ grid:{ color:'#22283d' }, ticks:{ callback:function(v){ return mode==='bps' ? fmtBps(v) : (v||0).toLocaleString(); } } } }
    }
  });
  buildLegend(legendEl, series.map(function(s){return s.router;}), series.map(function(_,i){return palette[i%palette.length];}));
  return chart;
}
async function loadAllRoutersCharts(){
  var section = document.getElementById('allRoutersSection');
  if(!section) return;
  if(routerSelect.value){ // specific router selected -> hide and destroy
    section.style.display = 'none';
    destroyChart(topRouterBwChart); topRouterBwChart=null;
    destroyChart(topRouterLossChart); topRouterLossChart=null;
    return;
  }
  // all routers
  var bw = await fetchRouterSeries('/api/metrics/throughput_by_router');
  var loss = await fetchRouterSeries('/api/metrics/packet_loss_by_router');
  section.style.display = (bw.series && bw.series.length) || (loss.series && loss.series.length) ? 'block' : 'none';
  if(section.style.display === 'none'){ destroyChart(topRouterBwChart); topRouterBwChart=null; destroyChart(topRouterLossChart); topRouterLossChart=null; return; }
  // re-render charts
  destroyChart(topRouterBwChart);
  topRouterBwChart = renderRouterSeriesChart('topRoutersBandwidth','legendBandwidth', bw, 'bps');
  destroyChart(topRouterLossChart);
  topRouterLossChart = renderRouterSeriesChart('topRoutersLoss','legendLoss', loss, 'loss');
}

async function refreshAll(){
  if(isRefreshing) return;
  isRefreshing = true;
  try{
    var now = Date.now();
    var fns = [function(){ return loadThroughput(); }, function(){ return loadIfaceThroughput(); }, function(){ return loadAllRoutersCharts(); }, function(){ return loadSessions(); }, function(){ return loadTops(); }];
    if(now - lastRoutersAt > 30000){
      fns.push(function(){ return loadRouters().then(function(){ lastRoutersAt = now; }); });
    }
    await runLimited(fns, 3);
  }catch(e){
    console.error(e);
    statusEl.textContent = 'Error: ' + (e && e.message ? e.message : String(e));
  }finally{
    isRefreshing = false;
  }
}
refreshBtn.addEventListener('click', refreshAll);
routerSelect.addEventListener('change', refreshAll);
rangeSelect.addEventListener('change', refreshAll);
refreshAll();
setInterval(refreshAll, 5000);
</script>
</body>
</html>`))
}

func parseTime(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	// Try RFC3339 (with timezone)
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, true
	}
	// Try HTML datetime-local (no timezone): YYYY-MM-DDTHH:MM[:SS]
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", v, time.Local); err == nil {
		return t, true
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04", v, time.Local); err == nil {
		return t, true
	}
	// Try unix seconds or milliseconds
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		// Heuristic: treat values > 1e12 as milliseconds
		if n > 1_000_000_000_000 {
			return time.Unix(0, n*int64(time.Millisecond)), true
		}
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
}

// currentTSDBRoot returns the active TSDB root directory used for filesystem logs.
func currentTSDBRoot() string {
	if tsdb != nil && strings.TrimSpace(tsdb.root) != "" {
		return tsdb.root
	}
	root := getenv("TSDB_ROOT", "E:\\DB")
	if st, err := os.Stat(root); err == nil && st.IsDir() {
		return root
	}
	fb := ".\\DB"
	_ = os.MkdirAll(fb, 0o755)
	return fb
}

type fsLogFilters struct {
	Src     string
	Dst     string
	Proto   string
	Port    int
	SrcPort int
	DstPort int
}

type fsLogItem struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	Bytes    int64  `json:"bytes"`
	Packets  int64  `json:"packets"`
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`
	SrcPort  int    `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
	Router   string `json:"router"`
	Side     string `json:"side"`
}

func parseHHMMSS(s string) (h, m, sec int, ok bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	sec, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, 0, false
	}
	return h, m, sec, true
}

func normalizeProto(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// if numeric, try map to name
	if n, err := strconv.Atoi(p); err == nil {
		if n >= 0 && n <= 255 {
			return strings.ToUpper(protocolNumberToString(byte(n)))
		}
	}
	return strings.ToUpper(p)
}

// scanIPLogs scans filesystem logs for the given IP and filters with pagination.
func scanIPLogs(root string, ip string, since, until time.Time, side string, filters fsLogFilters, offset, limit int) ([]fsLogItem, bool, error) {
	ip = strings.TrimSpace(ip)
	v4 := net.ParseIP(ip)
	if v4 == nil || v4.To4() == nil {
		return nil, false, fmt.Errorf("invalid ip")
	}
	// If the queried IP is not within our configured logging prefixes, it will not have its own per-IP folders.
	// In that case, fall back to scanning all stored logs within the requested time window and match by IP on either side.
	if !ipInLoggingPrefixes(ip) {
		return scanAllLogsForIP(root, ip, since, until, side, filters, offset, limit)
	}
	v4 = v4.To4()
	oct := v4.To4()
	o1, o2, o3, o4 := int(oct[0]), int(oct[1]), int(oct[2]), int(oct[3])
	since = since.UTC()
	until = until.UTC()
	if until.Before(since) {
		since, until = until, since
	}
	startHour := since.Truncate(time.Hour)
	endHour := until.Truncate(time.Hour)
	var names []string
	side = strings.ToLower(strings.TrimSpace(side))
	if side == "src" {
		names = []string{"src-port.log"}
	} else if side == "dst" {
		names = []string{"dst-port.log"}
	} else {
		names = []string{"src-port.log", "dst-port.log"}
	}
	protoFilter := normalizeProto(filters.Proto)
	matchIdx := 0
	var out []fsLogItem
	hasMore := false

	for h := startHour; !h.After(endHour); h = h.Add(time.Hour) {
		y := strconv.Itoa(h.Year())
		m := twoDigit(int(h.Month()))
		d := twoDigit(h.Day())
		hh := twoDigit(h.Hour())
		dir := filepath.Join(root, y, m, d, hh, strconv.Itoa(o1), strconv.Itoa(o2), strconv.Itoa(o3), strconv.Itoa(o4))
		for _, name := range names {
			path := filepath.Join(dir, name)
			sideName := ""
			if name == "src-port.log" {
				sideName = "src"
			} else if name == "dst-port.log" {
				sideName = "dst"
			}
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				// separate router
				router := ""
				prefix := line
				if idx := strings.LastIndex(line, " router="); idx >= 0 {
					prefix = strings.TrimSpace(line[:idx])
					router = strings.TrimSpace(strings.TrimPrefix(line[idx+1:], "router="))
				}
				fields := strings.Fields(prefix)
				if len(fields) < 7 {
					continue
				}
				startStr := fields[0]
				endStr := fields[1]
				bytesStr := fields[2]
				packetsStr := fields[3]
				proto := strings.ToUpper(fields[4])
				srcPair := fields[5]
				dstPair := fields[len(fields)-1] // in case '>' present
				if strings.Contains(dstPair, ">") && len(fields) >= 8 {
					// fields[6] should be '>' and fields[7] dst
					dstPair = fields[7]
				}
				// port/ip parsing
				srcIP, srcPort := "", 0
				dstIP, dstPort := "", 0
				if p := strings.Split(srcPair, ":"); len(p) == 2 {
					srcIP = p[0]
					srcPort, _ = strconv.Atoi(p[1])
				}
				if p := strings.Split(dstPair, ":"); len(p) == 2 {
					dstIP = p[0]
					dstPort, _ = strconv.Atoi(p[1])
				}
				b, _ := strconv.ParseInt(bytesStr, 10, 64)
				pk, _ := strconv.ParseInt(packetsStr, 10, 64)
				sh, sm, ss, ok1 := parseHHMMSS(startStr)
				eh, em, es, ok2 := parseHHMMSS(endStr)
				if !ok1 || !ok2 {
					continue
				}
				stAbs := time.Date(h.Year(), h.Month(), h.Day(), sh, sm, ss, 0, time.UTC)
				etAbs := time.Date(h.Year(), h.Month(), h.Day(), eh, em, es, 0, time.UTC)
				// time window
				if stAbs.Before(since) || stAbs.After(until) {
					continue
				}
				// filter
				if protoFilter != "" && !strings.EqualFold(proto, protoFilter) {
					continue
				}
				if filters.Src != "" && !strings.Contains(srcIP, filters.Src) {
					continue
				}
				if filters.Dst != "" && !strings.Contains(dstIP, filters.Dst) {
					continue
				}
				if filters.Port > 0 && !(srcPort == filters.Port || dstPort == filters.Port) {
					continue
				}
				if filters.SrcPort > 0 && srcPort != filters.SrcPort {
					continue
				}
				if filters.DstPort > 0 && dstPort != filters.DstPort {
					continue
				}

				matchIdx++
				if matchIdx <= offset {
					continue
				}
				if len(out) < limit {
					out = append(out, fsLogItem{
						Start: stAbs.UTC().Format(time.RFC3339),
						End:   etAbs.UTC().Format(time.RFC3339),
						Bytes: b, Packets: pk, Protocol: proto,
						SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort,
						Router: router,
						Side:   sideName,
					})
				} else {
					hasMore = true
					_ = f.Close()
					return out, hasMore, nil
				}
			}
			_ = f.Close()
		}
	}
	return out, hasMore, nil
}

// scanAllLogsForIP performs a time-bounded recursive scan across stored hourly folders
// and returns entries where the queried IP matches the selected side(s). It respects
// protocol/address/port filters and supports pagination via offset/limit.
func scanAllLogsForIP(root string, ip string, since, until time.Time, side string, filters fsLogFilters, offset, limit int) ([]fsLogItem, bool, error) {
	ip = strings.TrimSpace(ip)
	v4 := net.ParseIP(ip)
	if v4 == nil || v4.To4() == nil {
		return nil, false, fmt.Errorf("invalid ip")
	}
	since = since.UTC()
	until = until.UTC()
	if until.Before(since) {
		since, until = until, since
	}
	startHour := since.Truncate(time.Hour)
	endHour := until.Truncate(time.Hour)
	protoFilter := normalizeProto(filters.Proto)
	side = strings.ToLower(strings.TrimSpace(side))
	matchIdx := 0
	var out []fsLogItem
	hasMore := false
	stopErr := errors.New("scan-stop")
	for h := startHour; !h.After(endHour); h = h.Add(time.Hour) {
		y := strconv.Itoa(h.Year())
		m := twoDigit(int(h.Month()))
		d := twoDigit(h.Day())
		hh := twoDigit(h.Hour())
		hourDir := filepath.Join(root, y, m, d, hh)
		// Walk all existing IP folders for this hour
		_ = filepath.Walk(hourDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info == nil || info.IsDir() {
				return nil
			}
			base := filepath.Base(path)
			if base != "src-port.log" && base != "dst-port.log" {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				// separate router
				router := ""
				prefix := line
				if idx := strings.LastIndex(line, " router="); idx >= 0 {
					prefix = strings.TrimSpace(line[:idx])
					router = strings.TrimSpace(strings.TrimPrefix(line[idx+1:], "router="))
				}
				fields := strings.Fields(prefix)
				if len(fields) < 7 {
					continue
				}
				startStr := fields[0]
				endStr := fields[1]
				bytesStr := fields[2]
				packetsStr := fields[3]
				proto := strings.ToUpper(fields[4])
				srcPair := fields[5]
				dstPair := fields[len(fields)-1]
				if strings.Contains(dstPair, ">") && len(fields) >= 8 {
					dstPair = fields[7]
				}
				srcIP, srcPort := "", 0
				dstIP, dstPort := "", 0
				if p := strings.Split(srcPair, ":"); len(p) == 2 {
					srcIP = p[0]
					srcPort, _ = strconv.Atoi(p[1])
				}
				if p := strings.Split(dstPair, ":"); len(p) == 2 {
					dstIP = p[0]
					dstPort, _ = strconv.Atoi(p[1])
				}
				b, _ := strconv.ParseInt(bytesStr, 10, 64)
				pk, _ := strconv.ParseInt(packetsStr, 10, 64)
				sh, sm, ss, ok1 := parseHHMMSS(startStr)
				eh, em, es, ok2 := parseHHMMSS(endStr)
				if !ok1 || !ok2 {
					continue
				}
				stAbs := time.Date(h.Year(), h.Month(), h.Day(), sh, sm, ss, 0, time.UTC)
				etAbs := time.Date(h.Year(), h.Month(), h.Day(), eh, em, es, 0, time.UTC)
				if stAbs.Before(since) || stAbs.After(until) {
					continue
				}
				if protoFilter != "" && !strings.EqualFold(proto, protoFilter) {
					continue
				}
				if filters.Src != "" && !strings.Contains(srcIP, filters.Src) {
					continue
				}
				if filters.Dst != "" && !strings.Contains(dstIP, filters.Dst) {
					continue
				}
				if filters.Port > 0 && !(srcPort == filters.Port || dstPort == filters.Port) {
					continue
				}
				if filters.SrcPort > 0 && srcPort != filters.SrcPort {
					continue
				}
				if filters.DstPort > 0 && dstPort != filters.DstPort {
					continue
				}
				// Side/IP match logic: determine whether the requested IP matches this line per requested side
				matchSide := ""
				switch side {
				case "src":
					if srcIP == ip {
						matchSide = "src"
					} else {
						continue
					}
				case "dst":
					if dstIP == ip {
						matchSide = "dst"
					} else {
						continue
					}
				default:
					if srcIP == ip {
						matchSide = "src"
					} else if dstIP == ip {
						matchSide = "dst"
					} else {
						continue
					}
				}
				matchIdx++
				if matchIdx <= offset {
					continue
				}
				if len(out) < limit {
					out = append(out, fsLogItem{
						Start:    stAbs.UTC().Format(time.RFC3339),
						End:      etAbs.UTC().Format(time.RFC3339),
						Bytes:    b,
						Packets:  pk,
						Protocol: proto,
						SrcIP:    srcIP, SrcPort: srcPort,
						DstIP: dstIP, DstPort: dstPort,
						Router: router,
						Side:   matchSide,
					})
				} else {
					hasMore = true
					_ = f.Close()
					return stopErr
				}
			}
			_ = f.Close()
			return nil
		})
		if hasMore || (limit > 0 && len(out) >= limit) {
			break
		}
	}
	return out, hasMore, nil
}

// logsSearchHandler exposes the log search with filters and pagination.
func logsSearchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	ip := strings.TrimSpace(q.Get("ip"))
	if ip == "" {
		http.Error(w, "missing ip", http.StatusBadRequest)
		return
	}
	sinceStr := q.Get("since")
	if sinceStr == "" {
		sinceStr = q.Get("from")
	}
	untilStr := q.Get("until")
	if untilStr == "" {
		untilStr = q.Get("to")
	}
	var since, until time.Time
	if sinceStr != "" {
		if t, ok := parseTime(sinceStr); ok {
			since = t
		}
	}
	if untilStr != "" {
		if t, ok := parseTime(untilStr); ok {
			until = t
		}
	}
	if until.IsZero() {
		until = time.Now()
	}
	if since.IsZero() {
		since = until.Add(-1 * time.Hour)
	}

	side := q.Get("side") // src|dst|both
	page := 1
	if v := strings.TrimSpace(q.Get("page")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	pageSize := 10000
	if v := strings.TrimSpace(q.Get("page_size")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 10000 {
				n = 10000
			}
			pageSize = n
		}
	}
	offset := (page - 1) * pageSize

	// address and port filters with alternative names
	srcFilter := strings.TrimSpace(q.Get("src"))
	if srcFilter == "" {
		srcFilter = strings.TrimSpace(q.Get("src_address"))
	}
	if srcFilter == "" {
		srcFilter = strings.TrimSpace(q.Get("src-address"))
	}
	dstFilter := strings.TrimSpace(q.Get("dst"))
	if dstFilter == "" {
		dstFilter = strings.TrimSpace(q.Get("dst_address"))
	}
	if dstFilter == "" {
		dstFilter = strings.TrimSpace(q.Get("dst-address"))
	}
	parsePort := func(keys ...string) int {
		for _, k := range keys {
			v := strings.TrimSpace(q.Get(k))
			if v != "" {
				n, _ := strconv.Atoi(v)
				return n
			}
		}
		return 0
	}
	filters := fsLogFilters{
		Src: srcFilter,
		Dst: dstFilter,
		Proto: func() string {
			v := q.Get("proto")
			if v == "" {
				v = q.Get("protocol")
			}
			return v
		}(),
		Port:    parsePort("port"),
		SrcPort: parsePort("src_port", "src-port"),
		DstPort: parsePort("dst_port", "dst-port"),
	}

	root := currentTSDBRoot()
	items, more, err := scanIPLogs(root, ip, since, until, side, filters, offset, pageSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Collapse duplicate entries representing the same session across routers
	items = collapseLogItems(items)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ip":        ip,
		"since":     since.UTC().Format(time.RFC3339),
		"until":     until.UTC().Format(time.RFC3339),
		"page":      page,
		"page_size": pageSize,
		"has_more":  more,
		"next_page": func() int {
			if more {
				return page + 1
			}
			return 0
		}(),
		"items": items,
	})
}

// logsPageHandler serves a dedicated page for log searching in a separate window.
func logsPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>FlowAnalyzer - Logs</title>
<style>
 body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0b1020;color:#e6edf3}
 header, .controls{padding:1rem 1.25rem;border-bottom:1px solid #22283d;display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
 table{width:99%;border-collapse:collapse;background:#141a2f;border:1px solid #22283d;border-radius:10px;margin:1rem;overflow:hidden}
 th,td{padding:.4rem .5rem;border-bottom:1px solid #22283d;text-align:right}
 th:first-child, td:first-child{text-align:left}
 small.m{color:#8b96b1}
 select,input,button{background:#0f1529;color:#e6edf3;border:1px solid #253055;border-radius:6px;padding:.35rem .5rem}
 .muted{color:#8b96b1}
</style>
</head>
<body>
<header><h1 style="font-size:1rem;margin:0;color:#cbd4e6">Log Search</h1><small class="m">Dedicated window</small></header>
<div id="controls" class="controls">
  <label>From <input id="logFrom" type="datetime-local" step="1" style="width:220px"/></label>
  <label>To <input id="logTo" type="datetime-local" step="1" style="width:220px"/></label>
  <label>Side <select id="logSide"><option value="both" selected>both</option><option value="src">src</option><option value="dst">dst</option></select></label>
  <label>Src <input id="logSrc" style="width:160px"/></label>
  <label>Dst <input id="logDst" style="width:160px"/></label>
  <label>Proto <input id="logProto" style="width:80px"/></label>
  <label>Port <input id="logPort" style="width:80px"/></label>
  <button id="runLogSearch">Search</button>
  <button id="closeWin">Close</button>
</div>
<div class="muted" style="padding:0 1.25rem;">Defaults to last hour if From/To are empty. Max 10,000 rows per page. Live updates enabled.</div>
<table id="logTbl"><thead><tr>
  <th>Side</th><th>Start</th><th>End</th><th>Proto</th><th>Src</th><th>Dst</th><th>Bytes</th><th>Pkts</th><th>Router</th>
</tr></thead><tbody></tbody></table>
<div class="controls" style="border:0"><button id="logPrev">Prev</button><span class="muted">Page <span id="logPage">1</span></span><button id="logNext">Next 10000</button></div>
<script>
function getParam(name){ try{ return new URLSearchParams(location.search).get(name); }catch(e){ return null; } }
function ensureDefaultRange(){ const f=document.getElementById('logFrom'); const t=document.getElementById('logTo'); if(f && t && !f.value && !t.value){ function pad(n){ return String(n).padStart(2,'0'); } function toLocal(d){ return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds()); } const now=new Date(); const hourAgo=new Date(now.getTime()-3600*1000); f.value=toLocal(hourAgo); t.value=toLocal(now);} }
let logPage=1; let logHasMore=false; let ws=null; const ipParam=(getParam('src')||'');
function buildLogURL(){ const since=(document.getElementById('logFrom').value||'').trim(); const until=(document.getElementById('logTo').value||'').trim(); const side=document.getElementById('logSide').value; const src=(document.getElementById('logSrc').value||'').trim(); const dst=(document.getElementById('logDst').value||'').trim(); const proto=(document.getElementById('logProto').value||'').trim(); const port=(document.getElementById('logPort').value||'').trim(); const p=new URLSearchParams(); p.set('ip', ipParam); if(since) p.set('since', since); if(until) p.set('until', until); if(side && side!=='both') p.set('side', side); if(src) p.set('src', src); if(dst) p.set('dst', dst); if(proto) p.set('protocol', proto); if(port) p.set('port', port); p.set('page', String(logPage)); p.set('page_size', '10000'); return '/api/logs/search?'+p.toString(); }
function appendLogItem(it){ const tbody=document.querySelector('#logTbl tbody'); const tr=document.createElement('tr'); function td(t){ const d=document.createElement('td'); d.textContent=t; return d; } tr.appendChild(td(it.side||'')); tr.appendChild(td(it.start||'')); tr.appendChild(td(it.end||'')); tr.appendChild(td(it.protocol||'')); tr.appendChild(td((it.src_ip||'') + (it.src_port?(':'+it.src_port):''))); tr.appendChild(td((it.dst_ip||'') + (it.dst_port?(':'+it.dst_port):''))); tr.appendChild(td(String(it.bytes||0))); tr.appendChild(td(String(it.packets||0))); tr.appendChild(td(it.router||'')); tbody.appendChild(tr); }
function renderLogItems(items){ const tbody=document.querySelector('#logTbl tbody'); tbody.innerHTML=''; (items||[]).forEach(appendLogItem); }
async function runLogSearch(){ ensureDefaultRange(); document.getElementById('logPage').textContent=String(logPage); const r=await fetch(buildLogURL()); if(!r.ok){ console.error('log search http', r.status); return; } const data=await r.json(); logHasMore=!!data.has_more; renderLogItems(data.items||[]); document.getElementById('logNext').disabled = !logHasMore; document.getElementById('logPrev').disabled = logPage<=1; openWS(); }
function openWS(){ try{ if(ws){ ws.close(); } const since=(document.getElementById('logFrom').value||'').trim(); const until=(document.getElementById('logTo').value||'').trim(); const side=document.getElementById('logSide').value; const src=(document.getElementById('logSrc').value||'').trim(); const dst=(document.getElementById('logDst').value||'').trim(); const proto=(document.getElementById('logProto').value||'').trim(); const port=(document.getElementById('logPort').value||'').trim(); const p=new URLSearchParams(); if(ipParam) p.set('ip', ipParam); if(since) p.set('since', since); if(until) p.set('until', until); if(side && side!=='both') p.set('side', side); if(src) p.set('src', src); if(dst) p.set('dst', dst); if(proto) p.set('protocol', proto); if(port) p.set('port', port); const wsProto = (location.protocol==='https:')?'wss':'ws'; ws = new WebSocket(wsProto+'://'+location.host+'/ws/logs?'+p.toString()); ws.onmessage=function(ev){ try{ const it=JSON.parse(ev.data); appendLogItem(it);}catch(e){} }; ws.onopen=function(){}; ws.onerror=function(){}; }catch(e){} }
function init(){ const srcQ=getParam('src'); const auto=getParam('autoscroll'); const ip=ipParam; const srcEl=document.getElementById('logSrc'); if(srcEl){ srcEl.value = (srcQ||ip); } if(auto==='1'){ document.getElementById('controls').scrollIntoView({behavior:'smooth'}); } runLogSearch(); }
window.addEventListener('DOMContentLoaded', function(){ document.getElementById('runLogSearch').addEventListener('click', function(){ logPage=1; runLogSearch(); }); document.getElementById('closeWin').addEventListener('click', function(){ window.close(); }); document.getElementById('logNext').addEventListener('click', function(){ if(logHasMore){ logPage++; runLogSearch(); } }); document.getElementById('logPrev').addEventListener('click', function(){ if(logPage>1){ logPage--; runLogSearch(); } }); ['logFrom','logTo','logSide','logSrc','logDst','logProto','logPort'].forEach(function(id){ const el=document.getElementById(id); if(el){ el.addEventListener('change', function(){ openWS(); }); } }); init(); });
</script>
</body>
</html>`))
}

// wsLogsHandler upgrades to WebSocket and streams historical items for the given time window,
// then, if the end time is in the future, continues with live updates from the in-process writer.
func wsLogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	q := r.URL.Query()
	// Parse time window (defaults: last hour)
	var since, until time.Time
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		if t, ok := parseTime(v); ok {
			since = t
		}
	}
	if v := strings.TrimSpace(q.Get("until")); v != "" {
		if t, ok := parseTime(v); ok {
			until = t
		}
	}
	if until.IsZero() {
		until = time.Now()
	}
	if since.IsZero() {
		since = until.Add(-1 * time.Hour)
	}

	parsePort := func(keys ...string) int {
		for _, k := range keys {
			v := strings.TrimSpace(q.Get(k))
			if v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					return n
				}
			}
		}
		return 0
	}
	f := wsFilter{
		IP:   strings.TrimSpace(q.Get("ip")),
		Side: strings.ToLower(strings.TrimSpace(q.Get("side"))),
		Src:  strings.TrimSpace(q.Get("src")),
		Dst:  strings.TrimSpace(q.Get("dst")),
		Proto: normalizeProto(strings.TrimSpace(func() string {
			v := q.Get("protocol")
			if v == "" {
				v = q.Get("proto")
			}
			return v
		}())),
		Port:    parsePort("port"),
		SrcPort: parsePort("src_port", "src-port"),
		DstPort: parsePort("dst_port", "dst-port"),
	}

	// Stream historical items first (when IP is provided) to avoid concurrent writes with broadcaster.
	if f.IP != "" {
		root := currentTSDBRoot()
		side := strings.ToLower(strings.TrimSpace(q.Get("side")))
		filters := fsLogFilters{
			Src: strings.TrimSpace(q.Get("src")),
			Dst: strings.TrimSpace(q.Get("dst")),
			Proto: strings.TrimSpace(func() string {
				v := q.Get("protocol")
				if v == "" {
					v = q.Get("proto")
				}
				return v
			}()),
			Port:    parsePort("port"),
			SrcPort: parsePort("src_port", "src-port"),
			DstPort: parsePort("dst_port", "dst-port"),
		}
		// Use a high limit to stream all items in the window.
		if items, _, err := scanIPLogs(root, f.IP, since, until, side, filters, 0, 1_000_000); err == nil {
			items = collapseLogItems(items)
			for _, it := range items {
				_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := c.WriteJSON(it); err != nil {
					_ = c.Close()
					return
				}
			}
		}
	}

	// If end time is in the future, subscribe to live updates; otherwise, close the socket.
	if until.After(time.Now()) {
		wsMu.Lock()
		if wsMaxConns > 0 && len(wsConns) >= wsMaxConns {
			wsMu.Unlock()
			_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "too many connections"), time.Now().Add(1*time.Second))
			_ = c.Close()
			return
		}
		wsConns[c] = f
		wsMu.Unlock()
		// Read pump to detect close and cleanup
		go func(conn *websocket.Conn) {
			defer func() { wsMu.Lock(); delete(wsConns, conn); wsMu.Unlock(); _ = conn.Close() }()
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}(c)
	} else {
		// No live tailing requested; close gracefully after backlog
		_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(1*time.Second))
		_ = c.Close()
	}
}

// wsSessionsHandler upgrades to WebSocket and subscribes the client to live session updates (add/end),
// applying the same filter semantics as /ws/logs. Sends a snapshot of current active sessions first.
func wsSessionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	q := r.URL.Query()
	parsePort := func(keys ...string) int {
		for _, k := range keys {
			v := strings.TrimSpace(q.Get(k))
			if v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					return n
				}
			}
		}
		return 0
	}
	f := wsFilter{
		IP:   strings.TrimSpace(q.Get("ip")),
		Side: strings.ToLower(strings.TrimSpace(q.Get("side"))),
		Src:  strings.TrimSpace(q.Get("src")),
		Dst:  strings.TrimSpace(q.Get("dst")),
		Proto: normalizeProto(strings.TrimSpace(func() string {
			v := q.Get("protocol")
			if v == "" {
				v = q.Get("proto")
			}
			return v
		}())),
		Port:    parsePort("port"),
		SrcPort: parsePort("src_port", "src-port"),
		DstPort: parsePort("dst_port", "dst-port"),
	}

	// Send initial snapshot of currently active sessions from in-memory state.
	// We iterate a copy of the items from the concurrent map to avoid holding locks during writes.
	for k, st := range store.flowStates.Items() {
		fs, ok := flowSessionFromKey(k, st)
		if !ok {
			continue
		}
		// Populate running totals and last timestamp
		fs.Timestamp = st.LastExport
		fs.Bytes = st.SumBytes
		fs.Packets = st.SumPkts
		// Prefer historical routers path if known via dedup owners
		sig := flowSig(fs)
		if owner, ok := store.dedupOwners.Get(sig); ok {
			if len(owner.Routers) > 0 {
				fs.Routers = strings.Join(owner.Routers, ",")
			} else {
				fs.Routers = fs.Router
			}
		}
		if !wsMatches(f, fs) {
			continue
		}
		row := wsSessRow{
			Start: func() string {
				stt := fs.Start
				if stt.IsZero() {
					stt = fs.Timestamp
				}
				return stt.UTC().Format(time.RFC3339)
			}(),
			Last:     fs.Timestamp.UTC().Format(time.RFC3339),
			Protocol: strings.ToUpper(fs.Protocol),
			SrcIP:    fs.SrcIP,
			SrcPort:  fs.SrcPort,
			DstIP:    fs.DstIP,
			DstPort:  fs.DstPort,
			Bytes: func() int64 {
				if fs.Bytes < 0 {
					return 0
				}
				return fs.Bytes
			}(),
			Packets: func() int64 {
				if fs.Packets < 0 {
					return 0
				}
				return fs.Packets
			}(),
			Router: func() string {
				if strings.TrimSpace(fs.Routers) != "" {
					return fs.Routers
				}
				return fs.Router
			}(),
		}
		ev := wsSessEvent{Event: "add", Key: wsSessKey(fs), Session: row}
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := c.WriteJSON(ev); err != nil {
			_ = c.Close()
			return
		}
	}

	// Register connection for live updates after snapshot
	wsSessMu.Lock()
	if wsMaxConns > 0 && len(wsSessConns) >= wsMaxConns {
		wsSessMu.Unlock()
		_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "too many connections"), time.Now().Add(1*time.Second))
		_ = c.Close()
		return
	}
	wsSessConns[c] = f
	wsSessMu.Unlock()
	// Read pump
	go func(conn *websocket.Conn) {
		defer func() { wsSessMu.Lock(); delete(wsSessConns, conn); wsSessMu.Unlock(); _ = conn.Close() }()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}(c)
}

// getenv returns a configuration value with precedence: Environment > INI file > default.
func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	if v, ok := getINI(k); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

// getenvBool reads a configuration value as a boolean with a default.
// Truthy values: 1, true, yes, y, on (case-insensitive).
// Falsy values: 0, false, no, n, off (case-insensitive).
func getenvBool(k string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(k)))
	if v == "" {
		if iniV, ok := getINI(k); ok {
			v = strings.TrimSpace(strings.ToLower(iniV))
		}
	}
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

// getenvInt reads a configuration value as int with default value.
func getenvInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		if iniV, ok := getINI(k); ok {
			v = strings.TrimSpace(iniV)
		}
	}
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// parseCIDRList parses a comma/space/semicolon-separated list of CIDRs and returns IPv4 networks.
func parseCIDRList(s string) []*net.IPNet {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	seps := []string{",", ";", "\n", "\t", " "}
	for _, sep := range seps {
		s = strings.ReplaceAll(s, sep, ",")
	}
	parts := strings.Split(s, ",")
	var out []*net.IPNet
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil || n == nil {
			continue
		}
		if n.IP.To4() == nil {
			continue // we only log IPv4 currently
		}
		out = append(out, n)
	}
	return out
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		dur := time.Since(start)
		log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, dur)
	})
}

// gzip middleware for responses when client supports it. Skips WebSocket upgrades.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if !g.wroteHeader {
		g.wroteHeader = true
		h := g.Header()
		h.Del("Content-Length")
		h.Set("Content-Encoding", "gzip")
		h.Add("Vary", "Accept-Encoding")
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	return g.gz.Write(b)
}

func (g *gzipResponseWriter) Flush() {
	_ = g.gz.Flush()
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

var gzipPool = sync.Pool{New: func() any {
	w, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	return w
}}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only compress if client accepts gzip and not a WebSocket upgrade
		ae := strings.ToLower(r.Header.Get("Accept-Encoding"))
		if r.Method == http.MethodHead || !strings.Contains(ae, "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		conn := strings.ToLower(r.Header.Get("Connection"))
		up := strings.ToLower(r.Header.Get("Upgrade"))
		if strings.Contains(conn, "upgrade") || up == "websocket" {
			next.ServeHTTP(w, r)
			return
		}
		// Get a gzip writer from pool
		gz := gzipPool.Get().(*gzip.Writer)
		gz.Reset(w)
		defer func() {
			_ = gz.Close()
			gz.Reset(io.Discard)
			gzipPool.Put(gz)
		}()
		grw := &gzipResponseWriter{ResponseWriter: w, gz: gz}
		next.ServeHTTP(grw, r)
	})
}

// maxClockSkew is the tolerated difference between exporter time and server receive time
var maxClockSkew = 15 * time.Minute

// adjustBaseTime compares the exporter-provided export time with the server receive time.
// If the absolute skew exceeds maxClockSkew, it returns recvTime as base and the skew delta
// to be optionally applied to absolute flowStart/End timestamps (e.g., IPFIX).
// Otherwise it returns exportTime as base and zero skew.
func adjustBaseTime(exportTime time.Time, recvTime time.Time) (base time.Time, shift time.Duration, applied bool) {
	skew := recvTime.Sub(exportTime)
	if skew < 0 {
		if -skew > maxClockSkew {
			return recvTime, skew, true
		}
	} else if skew > maxClockSkew {
		return recvTime, skew, true
	}
	return exportTime, 0, false
}

// startUDPCollectorWithWorkers starts a UDP listener and processes packets with a bounded worker pool to cap memory usage.
func startUDPCollectorWithWorkers(ctx context.Context, addr, name string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Printf("%s resolve error: %v", strings.ToLower(name), err)
		return
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("%s listen error: %v", strings.ToLower(name), err)
		return
	}
	log.Printf("%s UDP collector listening on %s (workers=%d queue=%d)", name, addr, collectorWorkers, collectorQueue)
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	type udpPacket struct {
		data []byte
		src  *net.UDPAddr
		recv time.Time
	}
	queue := make(chan udpPacket, collectorQueue)
	// Start workers
	for i := 0; i < collectorWorkers; i++ {
		go func(id int) {
			for {
				select {
				case <-ctx.Done():
					return
				case pkt := <-queue:
					records := parseNetFlowPacket(pkt.data, pkt.src, pkt.recv)
					if len(records) == 0 {
						continue
					}
					fillCountries(records)
					store.AddMany(records)
				}
			}
		}(i)
	}

	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if ctx.Err() != nil {
				return
			}
			log.Printf("%s read error: %v", strings.ToLower(name), err)
			continue
		}
		recvTime := time.Now()
		b := make([]byte, n)
		copy(b, buf[:n])
		pkt := udpPacket{data: b, src: src, recv: recvTime}
		select {
		case <-ctx.Done():
			return
		case queue <- pkt:
		}
	}
}

// startFlowCollectors starts UDP listeners for NetFlow (v1/v5/v9) and IPFIX (v10) based on env vars.
func startFlowCollectors(ctx context.Context) {
	nfAddr := getenv("NETFLOW_ADDR", "0.0.0.0:2055")
	ipfixAddr := getenv("IPFIX_ADDR", "0.0.0.0:4739")
	if nfAddr != "" {
		go startUDPCollectorWithWorkers(ctx, nfAddr, "NETFLOW")
	}
	if ipfixAddr != "" {
		go startUDPCollectorWithWorkers(ctx, ipfixAddr, "IPFIX")
	}
}

func startNetFlowCollector(ctx context.Context, addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Printf("netflow resolve error: %v", err)
		return
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("netflow listen error: %v", err)
		return
	}
	log.Printf("NetFlow UDP collector listening on %s", addr)
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if ctx.Err() != nil {
				return
			}
			log.Printf("netflow read error: %v", err)
			continue
		}
		recvTime := time.Now()
		records := parseNetFlowPacket(buf[:n], src, recvTime)
		for _, rec := range records {
			r := rec
			go func(s FlowSession) {
				ss := []FlowSession{s}
				fillCountries(ss)
				store.AddMany(ss)
			}(r)
		}
	}
}

func startIPFIXCollector(ctx context.Context, addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Printf("ipfix resolve error: %v", err)
		return
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("ipfix listen error: %v", err)
		return
	}
	log.Printf("IPFIX UDP collector listening on %s", addr)
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if ctx.Err() != nil {
				return
			}
			log.Printf("ipfix read error: %v", err)
			continue
		}
		recvTime := time.Now()
		records := parseNetFlowPacket(buf[:n], src, recvTime) // parser handles v10 as IPFIX
		for _, rec := range records {
			r := rec
			go func(s FlowSession) {
				ss := []FlowSession{s}
				fillCountries(ss)
				store.AddMany(ss)
			}(r)
		}
	}
}

// parseNetFlowPacket parses NetFlow v1, v5 packets and produces FlowSession records.
// For v9 and IPFIX (v10), it creates a placeholder session noting packet receipt.
// Minimal template cache and parsing for NetFlow v9 and IPFIX v10 to extract core fields.
// This is not a full implementation but handles common exporters (e.g., MikroTik) and elements.

type ipfixField struct {
	ID         uint16
	Length     uint16
	Enterprise uint32 // 0 if none
}

type ipfixTemplate struct {
	ID     uint16
	Fields []ipfixField
}

var (
	templatesMu   sync.RWMutex
	templateStore = make(map[string]map[uint16]ipfixTemplate) // key: router+domain -> templateID -> template
)

func tplKey(router string, domain uint32) string {
	return fmt.Sprintf("%s/%d", router, domain)
}

func readUintBE(b []byte) uint64 {
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	case 8:
		return binary.BigEndian.Uint64(b)
	default:
		var v uint64
		for _, x := range b { // generic big-endian
			v = (v << 8) | uint64(x)
		}
		return v
	}
}

func parseV9(p []byte, router string, recvTime time.Time) []FlowSession {
	be := binary.BigEndian
	if len(p) < 24 {
		return nil
	}
	_ = be.Uint16(p[0:2])           // version (9)
	count := be.Uint16(p[2:4])      // flowset count
	sysUptime := be.Uint32(p[4:8])  // ms
	unixSecs := be.Uint32(p[8:12])  // seconds
	_ = be.Uint32(p[12:16])         // sequence
	sourceID := be.Uint32(p[16:20]) // observation domain ID analogue
	// establish base time with clock-skew tolerance
	exportBase := time.Unix(int64(unixSecs), 0)
	base, _, _ := adjustBaseTime(exportBase, recvTime)
	_ = sysUptime
	_ = count

	off := 20
	var out []FlowSession
	key := tplKey(router, sourceID)
	for off+4 <= len(p) {
		setID := be.Uint16(p[off : off+2])
		setLen := int(be.Uint16(p[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(p) {
			break
		}
		body := p[off+4 : off+setLen]
		if setID == 0 { // template set
			pos := 0
			templatesMu.Lock()
			m := templateStore[key]
			if m == nil {
				m = make(map[uint16]ipfixTemplate)
				templateStore[key] = m
			}
			for pos+4 <= len(body) {
				tid := be.Uint16(body[pos : pos+2])
				fc := int(be.Uint16(body[pos+2 : pos+4]))
				pos += 4
				fields := make([]ipfixField, 0, fc)
				for i := 0; i < fc && pos+4 <= len(body); i++ {
					id := be.Uint16(body[pos : pos+2])
					ln := be.Uint16(body[pos+2 : pos+4])
					pos += 4
					fields = append(fields, ipfixField{ID: id, Length: ln})
				}
				m[tid] = ipfixTemplate{ID: tid, Fields: fields}
			}
			templatesMu.Unlock()
		} else if setID > 255 {
			// data set; setID == templateID
			templatesMu.RLock()
			tpl, ok := templateStore[key][setID]
			templatesMu.RUnlock()
			if !ok || len(tpl.Fields) == 0 {
				off += setLen
				continue
			}
			recLen := 0
			for _, f := range tpl.Fields {
				recLen += int(f.Length)
			}
			pos := 0
			for recLen > 0 && pos+recLen <= len(body) {
				rec := body[pos : pos+recLen]
				pos += recLen
				var s FlowSession
				s.Router = router
				s.Timestamp = base
				var off2 int
				for _, f := range tpl.Fields {
					fld := rec[off2 : off2+int(f.Length)]
					off2 += int(f.Length)
					switch f.ID {
					case 8: // sourceIPv4Address
						if len(fld) == 4 {
							s.SrcIP = net.IP(fld).String()
						}
					case 12: // destinationIPv4Address
						if len(fld) == 4 {
							s.DstIP = net.IP(fld).String()
						}
					case 7: // sourceTransportPort
						s.SrcPort = int(readUintBE(fld))
					case 11: // destinationTransportPort
						s.DstPort = int(readUintBE(fld))
					case 4: // protocolIdentifier
						if len(fld) > 0 {
							s.Protocol = protocolNumberToString(fld[0])
						}
					case 1: // octetDeltaCount
						s.Bytes = int64(readUintBE(fld))
					case 2: // packetDeltaCount
						s.Packets = int64(readUintBE(fld))
					case 85: // octetTotalCount
						s.CumBytes = int64(readUintBE(fld))
					case 86: // packetTotalCount
						s.CumPackets = int64(readUintBE(fld))
					case 136: // flowEndReason
						s.EndReason = int(readUintBE(fld))
					case 24: // postPacketDeltaCount
						s.PostPackets = int64(readUintBE(fld))
					case 21: // last_switched (ms since boot)
						ms := uint32(readUintBE(fld))
						d := time.Duration(int64(int64(sysUptime)-int64(ms))) * time.Millisecond
						s.End = base.Add(-d)
					case 22: // first_switched (ms since boot)
						ms := uint32(readUintBE(fld))
						d := time.Duration(int64(int64(sysUptime)-int64(ms))) * time.Millisecond
						s.Start = base.Add(-d)
					case 152: // droppedPacketDeltaCount
						s.DroppedPackets = int64(readUintBE(fld))
					case 10: // ingressInterface
						s.InIf = int(readUintBE(fld))
					case 14: // egressInterface
						s.OutIf = int(readUintBE(fld))
					}
				}
				if s.SrcIP != "" || s.DstIP != "" {
					out = append(out, s)
				}
			}
		}
		off += setLen
	}
	return out
}

func parseIPFIX(p []byte, router string, recvTime time.Time) []FlowSession {
	be := binary.BigEndian
	if len(p) < 16 {
		return nil
	}
	_ = be.Uint16(p[0:2]) // version (10)
	length := int(be.Uint16(p[2:4]))
	exportTime := be.Uint32(p[4:8])
	_ = be.Uint32(p[8:12]) // sequence
	domain := be.Uint32(p[12:16])
	// establish base time and skew
	exportBase := time.Unix(int64(exportTime), 0)
	base, _, _ := adjustBaseTime(exportBase, recvTime)
	if length > len(p) {
		length = len(p)
	}
	off := 16
	var out []FlowSession
	key := tplKey(router, domain)
	delta := base.Sub(time.Unix(int64(exportTime), 0))
	for off+4 <= length {
		setID := be.Uint16(p[off : off+2])
		setLen := int(be.Uint16(p[off+2 : off+4]))
		if setLen < 4 || off+setLen > length {
			break
		}
		body := p[off+4 : off+setLen]
		if setID == 2 { // template set
			pos := 0
			templatesMu.Lock()
			m := templateStore[key]
			if m == nil {
				m = make(map[uint16]ipfixTemplate)
				templateStore[key] = m
			}
			for pos+4 <= len(body) {
				tid := be.Uint16(body[pos : pos+2])
				fc := int(be.Uint16(body[pos+2 : pos+4]))
				pos += 4
				fields := make([]ipfixField, 0, fc)
				for i := 0; i < fc && pos+4 <= len(body); i++ {
					id := be.Uint16(body[pos : pos+2])
					ln := be.Uint16(body[pos+2 : pos+4])
					pos += 4
					ent := uint32(0)
					if (id & 0x8000) != 0 { // enterprise bit set
						id = id & 0x7FFF
						if pos+4 > len(body) {
							break
						}
						ent = be.Uint32(body[pos : pos+4])
						pos += 4
					}
					fields = append(fields, ipfixField{ID: id, Length: ln, Enterprise: ent})
				}
				m[tid] = ipfixTemplate{ID: tid, Fields: fields}
			}
			templatesMu.Unlock()
		} else if setID >= 256 { // data set
			templatesMu.RLock()
			tpl, ok := templateStore[key][setID]
			templatesMu.RUnlock()
			if !ok || len(tpl.Fields) == 0 {
				off += setLen
				continue
			}
			recLen := 0
			for _, f := range tpl.Fields {
				// variable-length not supported (0xFFFF); skip entire set if present
				if f.Length == 0xFFFF {
					recLen = -1
					break
				}
				recLen += int(f.Length)
			}
			if recLen <= 0 {
				off += setLen
				continue
			}
			pos := 0
			for pos+recLen <= len(body) {
				rec := body[pos : pos+recLen]
				pos += recLen
				var s FlowSession
				s.Router = router
				s.Timestamp = base
				var off2 int
				for _, f := range tpl.Fields {
					fld := rec[off2 : off2+int(f.Length)]
					off2 += int(f.Length)
					switch f.ID {
					case 8: // sourceIPv4Address
						if len(fld) == 4 {
							s.SrcIP = net.IP(fld).String()
						}
					case 12: // destinationIPv4Address
						if len(fld) == 4 {
							s.DstIP = net.IP(fld).String()
						}
					case 7: // sourceTransportPort
						s.SrcPort = int(readUintBE(fld))
					case 11: // destinationTransportPort
						s.DstPort = int(readUintBE(fld))
					case 4: // protocolIdentifier
						if len(fld) > 0 {
							s.Protocol = protocolNumberToString(fld[0])
						}
					case 1: // octetDeltaCount
						s.Bytes = int64(readUintBE(fld))
					case 2: // packetDeltaCount
						s.Packets = int64(readUintBE(fld))
					case 85: // octetTotalCount
						s.CumBytes = int64(readUintBE(fld))
					case 86: // packetTotalCount
						s.CumPackets = int64(readUintBE(fld))
					case 136: // flowEndReason
						s.EndReason = int(readUintBE(fld))
					case 24: // postPacketDeltaCount
						s.PostPackets = int64(readUintBE(fld))
					case 150: // flowStartSeconds
						s.Start = time.Unix(int64(readUintBE(fld)), 0)
					case 151: // flowEndSeconds
						s.End = time.Unix(int64(readUintBE(fld)), 0)
					case 152: // flowStartMilliseconds
						ms := int64(readUintBE(fld))
						s.Start = time.Unix(0, ms*int64(time.Millisecond))
					case 153: // flowEndMilliseconds
						ms := int64(readUintBE(fld))
						s.End = time.Unix(0, ms*int64(time.Millisecond))
					case 10: // ingressInterface
						s.InIf = int(readUintBE(fld))
					case 14: // egressInterface
						s.OutIf = int(readUintBE(fld))
					}
				}
				// apply delta shift to absolute start/end if exporter clock was skewed
				if delta != 0 {
					if !s.Start.IsZero() {
						s.Start = s.Start.Add(delta)
					}
					if !s.End.IsZero() {
						s.End = s.End.Add(delta)
					}
				}
				if s.SrcIP != "" || s.DstIP != "" {
					out = append(out, s)
				}
			}
		}
		off += setLen
	}
	return out
}

func parseNetFlowPacket(p []byte, src *net.UDPAddr, recvTime time.Time) []FlowSession {
	if len(p) < 4 {
		return nil
	}
	be := binary.BigEndian
	ver := be.Uint16(p[0:2])
	count := be.Uint16(p[2:4])
	router := ""
	if src != nil {
		router = src.IP.String()
	}
	switch ver {
	case 5:
		if len(p) < 24 {
			return nil
		}
		sysUptime := be.Uint32(p[4:8])
		_ = sysUptime
		unixSecs := be.Uint32(p[8:12])
		// compute base export time with clock-skew tolerance
		exportBase := time.Unix(int64(unixSecs), 0)
		base, _, _ := adjustBaseTime(exportBase, recvTime)
		headerLen := 24
		recSize := 48
		max := int(count)
		records := make([]FlowSession, 0, max)
		for i := 0; i < max; i++ {
			off := headerLen + i*recSize
			if off+recSize > len(p) {
				break
			}
			srcIP := net.IP(p[off+0 : off+4]).String()
			dstIP := net.IP(p[off+4 : off+8]).String()
			inIf := be.Uint16(p[off+12 : off+14])
			outIf := be.Uint16(p[off+14 : off+16])
			dPkts := be.Uint32(p[off+16 : off+20])
			dOctets := be.Uint32(p[off+20 : off+24])
			first := be.Uint32(p[off+24 : off+28])
			last := be.Uint32(p[off+28 : off+32])
			srcPort := be.Uint16(p[off+32 : off+34])
			dstPort := be.Uint16(p[off+34 : off+36])
			proto := p[off+38]
			exportTime := base
			start := exportTime.Add(-time.Duration(int64(sysUptime)-int64(first)) * time.Millisecond)
			end := exportTime.Add(-time.Duration(int64(sysUptime)-int64(last)) * time.Millisecond)
			s := FlowSession{
				Timestamp: exportTime,
				Start:     start,
				End:       end,
				Router:    router,
				SrcIP:     srcIP,
				SrcPort:   int(srcPort),
				DstIP:     dstIP,
				DstPort:   int(dstPort),
				Protocol:  protocolNumberToString(proto),
				Bytes:     int64(dOctets),
				Packets:   int64(dPkts),
				EndReason: 1, // v5 exports are final records for the flow snapshot
				Notes:     "netflow v5",
				InIf:      int(inIf),
				OutIf:     int(outIf),
			}
			records = append(records, s)
		}
		return records
	case 1:
		// v1 header is 16 bytes (approx.), but first fields align with v5 for our needs
		if len(p) < 16 {
			return nil
		}
		sysUptime := be.Uint32(p[4:8])
		_ = sysUptime
		unixSecs := be.Uint32(p[8:12])
		headerLen := 16
		recSize := 48
		max := int(count)
		records := make([]FlowSession, 0, max)
		for i := 0; i < max; i++ {
			off := headerLen + i*recSize
			if off+recSize > len(p) {
				break
			}
			srcIP := net.IP(p[off+0 : off+4]).String()
			dstIP := net.IP(p[off+4 : off+8]).String()
			inIf := be.Uint16(p[off+12 : off+14])
			outIf := be.Uint16(p[off+14 : off+16])
			dPkts := be.Uint32(p[off+16 : off+20])
			dOctets := be.Uint32(p[off+20 : off+24])
			srcPort := be.Uint16(p[off+32 : off+34])
			dstPort := be.Uint16(p[off+34 : off+36])
			proto := p[off+38]
			exportBase := time.Unix(int64(unixSecs), 0)
			base, _, _ := adjustBaseTime(exportBase, recvTime)
			ts := base
			s := FlowSession{
				Timestamp: ts,
				Router:    router,
				SrcIP:     srcIP,
				SrcPort:   int(srcPort),
				DstIP:     dstIP,
				DstPort:   int(dstPort),
				Protocol:  protocolNumberToString(proto),
				Bytes:     int64(dOctets),
				Packets:   int64(dPkts),
				Notes:     "netflow v1",
				InIf:      int(inIf),
				OutIf:     int(outIf),
			}
			records = append(records, s)
		}
		return records
	case 9:
		return parseV9(p, router, recvTime)
	case 10:
		return parseIPFIX(p, router, recvTime)
	default:
		return []FlowSession{{
			Timestamp: time.Now(),
			Router:    router,
			Protocol:  fmt.Sprintf("NETFLOWV%d", ver),
			Notes:     fmt.Sprintf("received unsupported NetFlow/IPFIX version %d len=%d", ver, len(p)),
		}}
	}
}

func protocolNumberToString(p byte) string {
	switch p {
	case 0:
		return "HOPOPT" // IPv6 Hop-by-Hop Options
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IPv4" // IP-in-IP encapsulation
	case 6:
		return "TCP"
	case 8:
		return "EGP"
	case 9:
		return "IGP"
	case 17:
		return "UDP"
	case 33:
		return "DCCP"
	case 41:
		return "IPv6"
	case 43:
		return "IPv6-Route"
	case 44:
		return "IPv6-Frag"
	case 46:
		return "RSVP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 59:
		return "IPv6-NoNxt"
	case 60:
		return "IPv6-Opts"
	case 88:
		return "EIGRP"
	case 89:
		return "OSPF"
	case 94:
		return "IPIP" // IP-within-IP Encapsulation Protocol
	case 103:
		return "PIM"
	case 108:
		return "IPComp"
	case 112:
		return "VRRP"
	case 115:
		return "L2TP"
	case 132:
		return "SCTP"
	case 136:
		return "UDPLite"
	case 137:
		return "MPLS-in-IP"
	case 255:
		return "Reserved"
	default:
		return fmt.Sprintf("IP-%d", p)
	}
}

// flowKey builds a key to identify a flow across interim exports
func flowKey(s FlowSession) string {
	return fmt.Sprintf("%s|%s|%d|%s|%d|%s|%d|%d", s.Router, s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, s.Protocol, s.InIf, s.OutIf)
}

// flowSig builds a cross-router deduplication signature for a directional flow (5-tuple)
func flowSig(s FlowSession) string {
	// Note: do not include Router or interfaces here; we deduplicate across routers
	// Normalize protocol and treat ICMP families as portless to avoid duplicate rows across exporters
	proto := strings.ToUpper(strings.TrimSpace(s.Protocol))
	srcPort := s.SrcPort
	dstPort := s.DstPort
	if proto == "ICMP" || proto == "ICMPV6" {
		srcPort = 0
		dstPort = 0
	}
	return fmt.Sprintf("%s|%d|%s|%d|%s", s.SrcIP, srcPort, s.DstIP, dstPort, proto)
}

// wsSessKey returns the key used for WebSocket live session updates. When dedup
// is enabled, we want a single row per flow signature regardless of router, so
// we use flowSig. Otherwise, fall back to flowKey (includes router).
func wsSessKey(s FlowSession) string {
	if dedupEnable {
		return flowSig(s)
	}
	return flowKey(s)
}

// flowSessionFromKey reconstructs a FlowSession identity from a flowKey and flowTrack state.
// Expected key format: Router|SrcIP|SrcPort|DstIP|DstPort|Protocol|InIf|OutIf
func flowSessionFromKey(key string, ft flowTrack) (FlowSession, bool) {
	parts := strings.Split(key, "|")
	if len(parts) != 8 {
		return FlowSession{}, false
	}
	srcPort, err1 := strconv.Atoi(parts[2])
	dstPort, err2 := strconv.Atoi(parts[4])
	inIf, err3 := strconv.Atoi(parts[6])
	outIf, err4 := strconv.Atoi(parts[7])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return FlowSession{}, false
	}
	fs := FlowSession{
		Start:    ft.Start,
		Router:   parts[0],
		SrcIP:    parts[1],
		SrcPort:  srcPort,
		DstIP:    parts[3],
		DstPort:  dstPort,
		Protocol: parts[5],
		InIf:     inIf,
		OutIf:    outIf,
	}
	return fs, true
}

// effectiveEndOrTs returns End if set, otherwise Timestamp.
func effectiveEndOrTs(s FlowSession) time.Time {
	if !s.End.IsZero() {
		return s.End
	}
	return s.Timestamp
}

// minuteBucketUnix returns the unix timestamp of the start of the minute for t (UTC)
func minuteBucketUnix(t time.Time) int64 { return t.UTC().Truncate(time.Minute).Unix() }

// fiveMinuteBucketUnix returns the unix timestamp of the start of the 5-minute bucket for t (UTC)
func fiveMinuteBucketUnix(t time.Time) int64 { return t.UTC().Truncate(5 * time.Minute).Unix() }

// minuteFromKey parses a key formatted as "<prefix>|<unixMinute>" and returns the minute unix time.
func minuteFromKey(k string) (int64, bool) {
	idx := strings.LastIndex(k, "|")
	if idx < 0 || idx+1 >= len(k) {
		return 0, false
	}
	n, err := strconv.ParseInt(k[idx+1:], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// indexAndSummarize updates srcMap and minute summaries for the provided sessions.
func (s *Store) indexAndSummarize(items []FlowSession) {
	for _, item := range items {
		sess := item // capture
		// Removed per-src session index maintenance to reduce CPU and memory overhead.
		// Previously: s.srcMap nested map with copy-on-write pruning on every ingestion.

		// Update minute summaries (tx for SrcIP, rx for DstIP, and per-protocol)
		if sess.Bytes > 0 || sess.Packets > 0 {
			m := minuteBucketUnix(effectiveEndOrTs(sess))
			txKey := fmt.Sprintf("%s|%d", sess.SrcIP, m)
			rxKey := fmt.Sprintf("%s|%d", sess.DstIP, m)
			proto := strings.ToUpper(strings.TrimSpace(sess.Protocol))
			if proto == "" {
				proto = "UNK"
			}
			ppKey := fmt.Sprintf("%s|%d", proto, m)

			add := minuteAcc{Bytes: sess.Bytes, Packets: sess.Packets}
			// per-IP totals
			s.ipMinuteTx.Upsert(txKey, add, func(exist bool, cur, newVal minuteAcc) minuteAcc {
				if exist {
					cur.Bytes += newVal.Bytes
					cur.Packets += newVal.Packets
					return cur
				}
				return newVal
			})
			s.ipMinuteRx.Upsert(rxKey, add, func(exist bool, cur, newVal minuteAcc) minuteAcc {
				if exist {
					cur.Bytes += newVal.Bytes
					cur.Packets += newVal.Packets
					return cur
				}
				return newVal
			})
			// global per-protocol totals
			s.protoMinute.Upsert(ppKey, add, func(exist bool, cur, newVal minuteAcc) minuteAcc {
				if exist {
					cur.Bytes += newVal.Bytes
					cur.Packets += newVal.Packets
					return cur
				}
				return newVal
			})
			// per-IP per-protocol split
			ippTxKey := fmt.Sprintf("%s|%s|%d", sess.SrcIP, proto, m)
			ippRxKey := fmt.Sprintf("%s|%s|%d", sess.DstIP, proto, m)
			s.ipProtoTx.Upsert(ippTxKey, add, func(exist bool, cur, newVal minuteAcc) minuteAcc {
				if exist {
					cur.Bytes += newVal.Bytes
					cur.Packets += newVal.Packets
					return cur
				}
				return newVal
			})
			s.ipProtoRx.Upsert(ippRxKey, add, func(exist bool, cur, newVal minuteAcc) minuteAcc {
				if exist {
					cur.Bytes += newVal.Bytes
					cur.Packets += newVal.Packets
					return cur
				}
				return newVal
			})
			// per IP pair (directional) totals using 5-minute buckets
			m5 := fiveMinuteBucketUnix(effectiveEndOrTs(sess))
			pairKey := fmt.Sprintf("%s|%s|%d", sess.SrcIP, sess.DstIP, m5)
			s.pairMinute.Upsert(pairKey, add, func(exist bool, cur, newVal minuteAcc) minuteAcc {
				if exist {
					cur.Bytes += newVal.Bytes
					cur.Packets += newVal.Packets
					return cur
				}
				return newVal
			})
			// per IP pair session count: count every observed session record (compatibility with UI peers expectations)
			s.pairMinuteSess.Upsert(pairKey, 1, func(exist bool, cur, newVal int64) int64 {
				if exist {
					return cur + 1
				}
				return newVal
			})
		}
	}
}

// pruneSummaries removes minute summary keys older than 8 hours.
func (s *Store) pruneSummaries() {
	retH := summariesRetentionHours
	if retH <= 0 {
		retH = 8
	}
	cut := time.Now().Add(-time.Duration(retH) * time.Hour).UTC().Truncate(time.Minute).Unix()
	for k := range s.ipMinuteTx.Items() {
		if m, ok := minuteFromKey(k); ok && m < cut {
			s.ipMinuteTx.Remove(k)
		}
	}
	for k := range s.ipMinuteRx.Items() {
		if m, ok := minuteFromKey(k); ok && m < cut {
			s.ipMinuteRx.Remove(k)
		}
	}
	for k := range s.protoMinute.Items() {
		if m, ok := minuteFromKey(k); ok && m < cut {
			s.protoMinute.Remove(k)
		}
	}
	for k := range s.ipProtoTx.Items() {
		if m, ok := minuteFromKey(k); ok && m < cut {
			s.ipProtoTx.Remove(k)
		}
	}
	for k := range s.ipProtoRx.Items() {
		if m, ok := minuteFromKey(k); ok && m < cut {
			s.ipProtoRx.Remove(k)
		}
	}
	for k := range s.pairMinute.Items() {
		if m, ok := minuteFromKey(k); ok && m < cut {
			s.pairMinute.Remove(k)
		}
	}
	for k := range s.pairMinuteSess.Items() {
		if m, ok := minuteFromKey(k); ok && m < cut {
			s.pairMinuteSess.Remove(k)
		}
	}
	// prune per-flow tracking states by inactivity (flowTimeoutMinutes)
	ftm := flowTimeoutMinutes
	if ftm <= 0 {
		ftm = 10
	}
	idleCutoff := time.Now().Add(-time.Duration(ftm) * time.Minute)
	// finalize and prune inactive flow states
	expired := make([]FlowSession, 0)
	for k, v := range s.flowStates.Items() {
		if v.LastExport.Before(idleCutoff) {
			// reconstruct session identity
			if fs, ok := flowSessionFromKey(k, v); ok {
				fs.Timestamp = v.LastExport
				fs.Start = v.Start
				fs.End = v.LastExport
				// Prefer exporter cumulative totals; otherwise, use accumulated deltas
				tb := v.LastCumBytes
				tp := v.LastCumPkts
				if tb == 0 && v.SumBytes > 0 {
					tb = v.SumBytes
				}
				if tp == 0 && v.SumPkts > 0 {
					tp = v.SumPkts
				}
				fs.Bytes = tb
				fs.Packets = tp
				expired = append(expired, fs)
			}
			// remove state
			s.flowStates.Remove(k)
		}
	}
	if len(expired) > 0 {
		// append to store
		s.mu.Lock()
		s.sessions = append(s.sessions, expired...)
		s.mu.Unlock()
		// update summaries
		s.indexAndSummarize(expired)
		// persist finals
		if tsdb != nil {
			tsdb.EnqueueMany(expired)
		}
		// broadcast
		for _, sfs := range expired {
			select {
			case newSessionsChan <- sfs:
			default:
			}
			select {
			case endedSessionsChan <- sfs:
			default:
			}
		}
	}
	// prune dedup owners
	if dedupEnable {
		now := time.Now()
		for k, v := range s.dedupOwners.Items() {
			if now.Sub(v.LastSeen) > dedupTTL {
				s.dedupOwners.Remove(k)
			}
		}
	}
}

// buildIPSeries builds aligned step points from minute summaries for a specific IP and map (tx or rx).
func (s *Store) buildIPSeries(m cmap.ConcurrentMap[string, minuteAcc], ip string, since, until time.Time, stepSec int) []map[string]any {
	if stepSec < 60 || stepSec%60 != 0 {
		stepSec = 60
	}
	step := time.Duration(stepSec) * time.Second
	startAligned := since.Truncate(step)
	var pts []map[string]any
	for t := startAligned; !t.After(until); t = t.Add(step) {
		end := t.Add(step)
		var b, p int64
		for mt := t.Truncate(time.Minute); mt.Before(end); mt = mt.Add(time.Minute) {
			mk := fmt.Sprintf("%s|%d", ip, minuteBucketUnix(mt))
			if acc, ok := m.Get(mk); ok {
				b += acc.Bytes
				p += acc.Packets
			}
		}
		bps := float64(b*8) / float64(stepSec)
		pts = append(pts, map[string]any{"ts": t.UTC().Format(time.RFC3339), "bytes": b, "packets": p, "bps": bps})
	}
	return pts
}

// ipViewHandler provides per-IP tx/rx series and session lists.
// It now builds series by scanning the filesystem logs (TSDB) instead of in-memory aggregates.
func ipViewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "missing 'ip' parameter", http.StatusBadRequest)
		return
	}
	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")
	stepSec := 60
	if v := r.URL.Query().Get("step"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			stepSec = n
		}
	}
	if stepSec < 60 || stepSec%60 != 0 {
		stepSec = 60
	}
	var since, until time.Time
	if sinceStr != "" {
		if t, ok := parseTime(sinceStr); ok {
			since = t
		}
	}
	if untilStr != "" {
		if t, ok := parseTime(untilStr); ok {
			until = t
		}
	}
	now := time.Now()
	if until.IsZero() {
		until = now
	}
	if since.IsZero() {
		since = until.Add(-1 * time.Hour)
	}
	// align start to step for consistent charting
	step := time.Duration(stepSec) * time.Second
	startAligned := since.Truncate(step)

	// Build series from filesystem logs
	buildSeries := func(side string) []map[string]any {
		root := currentTSDBRoot()
		// Collect all items for the window; page through if needed
		var items []fsLogItem
		offset := 0
		const pageSize = 100000
		for {
			batch, more, err := scanIPLogs(root, ip, since, until, side, fsLogFilters{}, offset, pageSize)
			if err != nil {
				break
			}
			items = append(items, batch...)
			if !more || len(batch) == 0 {
				break
			}
			offset += len(batch)
		}
		// Aggregate into per-minute bins using End time
		mins := make(map[int64]minuteAcc)
		for _, it := range items {
			et, ok := parseTime(it.End)
			if !ok {
				continue
			}
			m := minuteBucketUnix(et)
			acc := mins[m]
			acc.Bytes += it.Bytes
			acc.Packets += it.Packets
			mins[m] = acc
		}
		// Build step-aligned points by summing minute bins inside each step
		var pts []map[string]any
		for t := startAligned; !t.After(until); t = t.Add(step) {
			end := t.Add(step)
			var b, p int64
			for mt := t.Truncate(time.Minute); mt.Before(end); mt = mt.Add(time.Minute) {
				mu := minuteBucketUnix(mt)
				if acc, ok := mins[mu]; ok {
					b += acc.Bytes
					p += acc.Packets
				}
			}
			bps := float64(b*8) / float64(stepSec)
			pts = append(pts, map[string]any{"ts": t.UTC().Format(time.RFC3339), "bytes": b, "packets": p, "bps": bps})
		}
		return pts
	}

	tx := buildSeries("src")
	rx := buildSeries("dst")

	// Sessions lists omitted to minimize CPU: return empty lists.
	var asSrc, asDst []FlowSession

	payload := map[string]any{
		"ip":        ip,
		"since":     startAligned.UTC().Format(time.RFC3339),
		"until":     until.UTC().Format(time.RFC3339),
		"step":      stepSec,
		"tx_points": tx,
		"rx_points": rx,
		"as_src":    asSrc,
		"as_dst":    asDst,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// ipPageHandler serves a minimal page to inspect an IP's tx/rx and sessions.

// topIPsHandler returns top N IPs by total traffic with aligned series using minute summaries (tx+rx combined).
func topIPsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	stepSec := 60
	if v := r.URL.Query().Get("step"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			stepSec = n
		}
	}
	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")
	var since, until time.Time
	if sinceStr != "" {
		if t, ok := parseTime(sinceStr); ok {
			since = t
		}
	}
	if untilStr != "" {
		if t, ok := parseTime(untilStr); ok {
			until = t
		}
	}
	now := time.Now()
	if until.IsZero() {
		until = now
	}
	if since.IsZero() {
		since = until.Add(-1 * time.Hour)
	}
	if stepSec < 60 || stepSec%60 != 0 {
		stepSec = 60
	}
	step := time.Duration(stepSec) * time.Second
	startAligned := since.Truncate(step)

	// Tally totals per IP from minute summaries within window
	totals := make(map[string]int64)
	addFromMap := func(m cmap.ConcurrentMap[string, minuteAcc]) {
		for k, acc := range m.Items() {
			mUnix, ok := minuteFromKey(k)
			if !ok {
				continue
			}
			mt := time.Unix(mUnix, 0).UTC()
			if mt.Before(since) || mt.After(until) {
				continue
			}
			ip := k[:strings.LastIndex(k, "|")]
			totals[ip] += acc.Bytes
		}
	}
	addFromMap(store.ipMinuteTx)
	addFromMap(store.ipMinuteRx)

	// Pick top N IPs
	type item struct {
		IP    string
		Bytes int64
	}
	arr := make([]item, 0, len(totals))
	for ip, b := range totals {
		arr = append(arr, item{IP: ip, Bytes: b})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].Bytes == arr[j].Bytes {
			return arr[i].IP < arr[j].IP
		}
		return arr[i].Bytes > arr[j].Bytes
	})
	if limit > 0 && len(arr) > limit {
		arr = arr[:limit]
	}

	// Build series for each top IP by combining tx and rx per minute
	buildCombined := func(ip string) []map[string]any {
		pts := make([]map[string]any, 0)
		for t := startAligned; !t.After(until); t = t.Add(step) {
			end := t.Add(step)
			var b, p int64
			for mt := t.Truncate(time.Minute); mt.Before(end); mt = mt.Add(time.Minute) {
				mk := fmt.Sprintf("%s|%d", ip, minuteBucketUnix(mt))
				if acc, ok := store.ipMinuteTx.Get(mk); ok {
					b += acc.Bytes
					p += acc.Packets
				}
				if acc, ok := store.ipMinuteRx.Get(mk); ok {
					b += acc.Bytes
					p += acc.Packets
				}
			}
			bps := float64(b*8) / float64(stepSec)
			pts = append(pts, map[string]any{"ts": t.UTC().Format(time.RFC3339), "bytes": b, "packets": p, "bps": bps})
		}
		return pts
	}

	// Build output series
	type series struct {
		IP         string           `json:"ip"`
		TotalBytes int64            `json:"total_bytes"`
		Points     []map[string]any `json:"points"`
	}
	out := make([]series, 0, len(arr))
	for _, it := range arr {
		out = append(out, series{IP: it.IP, TotalBytes: it.Bytes, Points: buildCombined(it.IP)})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"since":  startAligned.UTC().Format(time.RFC3339),
		"until":  until.UTC().Format(time.RFC3339),
		"step":   stepSec,
		"series": out,
	})
}

// throughputByProtocolPrecomputedHandler returns global per-protocol aligned series using precomputed per-minute totals.
func throughputByProtocolPrecomputedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stepSec := 60
	if v := r.URL.Query().Get("step"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			stepSec = n
		}
	}
	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")
	var since, until time.Time
	if sinceStr != "" {
		if t, ok := parseTime(sinceStr); ok {
			since = t
		}
	}
	if untilStr != "" {
		if t, ok := parseTime(untilStr); ok {
			until = t
		}
	}
	now := time.Now()
	if until.IsZero() {
		until = now
	}
	if since.IsZero() {
		since = until.Add(-1 * time.Hour)
	}
	if stepSec < 60 || stepSec%60 != 0 {
		stepSec = 60
	}
	step := time.Duration(stepSec) * time.Second
	startAligned := since.Truncate(step)

	// Collect per-minute totals from store.protoMinute
	bins := make(map[string]map[int64]minuteAcc) // proto -> minute -> acc
	for k, acc := range store.protoMinute.Items() {
		mUnix, ok := minuteFromKey(k)
		if !ok {
			continue
		}
		mt := time.Unix(mUnix, 0).UTC()
		if mt.Before(since) || mt.After(until) {
			continue
		}
		proto := k[:strings.LastIndex(k, "|")]
		mm := bins[proto]
		if mm == nil {
			mm = make(map[int64]minuteAcc)
			bins[proto] = mm
		}
		mm[mUnix] = minuteAcc{Bytes: mm[mUnix].Bytes + acc.Bytes, Packets: mm[mUnix].Packets + acc.Packets}
	}

	// Build step-aligned series
	type point struct {
		Ts      string  `json:"ts"`
		Bytes   int64   `json:"bytes"`
		Packets int64   `json:"packets"`
		Bps     float64 `json:"bps"`
	}
	type series struct {
		Protocol   string  `json:"protocol"`
		TotalBytes int64   `json:"total_bytes"`
		Points     []point `json:"points"`
	}
	var protos []string
	for p := range bins {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	out := make([]series, 0, len(protos))
	for _, p := range protos {
		mm := bins[p]
		var pts []point
		var tb int64
		for t := startAligned; !t.After(until); t = t.Add(step) {
			end := t.Add(step)
			var b, pk int64
			for mt := t.Truncate(time.Minute); mt.Before(end); mt = mt.Add(time.Minute) {
				mUnix := minuteBucketUnix(mt)
				if a, ok := mm[mUnix]; ok {
					b += a.Bytes
					pk += a.Packets
				}
			}
			bps := float64(b*8) / float64(stepSec)
			pts = append(pts, point{Ts: t.UTC().Format(time.RFC3339), Bytes: b, Packets: pk, Bps: bps})
			tb += b
		}
		out = append(out, series{Protocol: p, TotalBytes: tb, Points: pts})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"since":  startAligned.UTC().Format(time.RFC3339),
		"until":  until.UTC().Format(time.RFC3339),
		"step":   stepSec,
		"series": out,
	})
}

// ipProtocolsHandler returns per-protocol aligned series for a specific IP using precomputed per-minute per-protocol maps.
func ipProtocolsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "missing 'ip' parameter", http.StatusBadRequest)
		return
	}
	stepSec := 60
	if v := r.URL.Query().Get("step"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			stepSec = n
		}
	}
	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")
	var since, until time.Time
	if sinceStr != "" {
		if t, ok := parseTime(sinceStr); ok {
			since = t
		}
	}
	if untilStr != "" {
		if t, ok := parseTime(untilStr); ok {
			until = t
		}
	}
	now := time.Now()
	if until.IsZero() {
		until = now
	}
	if since.IsZero() {
		since = until.Add(-1 * time.Hour)
	}
	if stepSec < 60 || stepSec%60 != 0 {
		stepSec = 60
	}
	step := time.Duration(stepSec) * time.Second
	startAligned := since.Truncate(step)

	bins := make(map[string]map[int64]minuteAcc) // proto -> ts -> acc
	// helper to add from map if key matches ip|proto|minute
	addFrom := func(m cmap.ConcurrentMap[string, minuteAcc]) {
		for k, acc := range m.Items() {
			last := strings.LastIndex(k, "|")
			if last < 0 {
				continue
			}
			mUnix, ok := minuteFromKey(k)
			if !ok {
				continue
			}
			mt := time.Unix(mUnix, 0).UTC()
			if mt.Before(since) || mt.After(until) {
				continue
			}
			pre := k[:last]
			mid := strings.LastIndex(pre, "|")
			if mid < 0 {
				continue
			}
			ipPart := pre[:mid]
			proto := pre[mid+1:]
			if ipPart != ip {
				continue
			}
			mm := bins[proto]
			if mm == nil {
				mm = make(map[int64]minuteAcc)
				bins[proto] = mm
			}
			mm[mUnix] = minuteAcc{Bytes: mm[mUnix].Bytes + acc.Bytes, Packets: mm[mUnix].Packets + acc.Packets}
		}
	}
	addFrom(store.ipProtoTx)
	addFrom(store.ipProtoRx)

	// Build step-aligned series
	type point struct {
		Ts      string  `json:"ts"`
		Bytes   int64   `json:"bytes"`
		Packets int64   `json:"packets"`
		Bps     float64 `json:"bps"`
	}
	type series struct {
		Protocol   string  `json:"protocol"`
		TotalBytes int64   `json:"total_bytes"`
		Points     []point `json:"points"`
	}
	var protos []string
	for p := range bins {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	out := make([]series, 0, len(protos))
	for _, p := range protos {
		mm := bins[p]
		var pts []point
		var tb int64
		for t := startAligned; !t.After(until); t = t.Add(step) {
			end := t.Add(step)
			var b, pk int64
			for mt := t.Truncate(time.Minute); mt.Before(end); mt = mt.Add(time.Minute) {
				mUnix := minuteBucketUnix(mt)
				if a, ok := mm[mUnix]; ok {
					b += a.Bytes
					pk += a.Packets
				}
			}
			bps := float64(b*8) / float64(stepSec)
			pts = append(pts, point{Ts: t.UTC().Format(time.RFC3339), Bytes: b, Packets: pk, Bps: bps})
			tb += b
		}
		out = append(out, series{Protocol: p, TotalBytes: tb, Points: pts})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ip":     ip,
		"since":  startAligned.UTC().Format(time.RFC3339),
		"until":  until.UTC().Format(time.RFC3339),
		"step":   stepSec,
		"series": out,
	})
}

// ipPeersHandler returns top peers communicating with the given IP using per-minute pair aggregates.
func ipPeersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "missing 'ip' parameter", http.StatusBadRequest)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	stepSec := 60
	if v := r.URL.Query().Get("step"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			stepSec = n
		}
	}
	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")
	var since, until time.Time
	if sinceStr != "" {
		if t, ok := parseTime(sinceStr); ok {
			since = t
		}
	}
	if untilStr != "" {
		if t, ok := parseTime(untilStr); ok {
			until = t
		}
	}
	now := time.Now()
	if until.IsZero() {
		until = now
	}
	if since.IsZero() {
		since = until.Add(-1 * time.Hour)
	}
	if stepSec < 60 || stepSec%60 != 0 {
		stepSec = 60
	}
	step := time.Duration(stepSec) * time.Second
	startAligned := since.Truncate(step)

	// Collect per-peer minute bins and totals (no CIDR filtering for peers endpoint)
	bins := make(map[string]map[int64]minuteAcc) // peer -> mUnix -> acc
	totals := make(map[string]int64)
	sessionTotals := make(map[string]int64)
	// CIDR filter bypassed for peers endpoint; include all peers regardless of configured UI/TSDB CIDR filters.
	for k, acc := range store.pairMinute.Items() {
		mUnix, ok := minuteFromKey(k)
		if !ok {
			continue
		}
		mt := time.Unix(mUnix, 0).UTC()
		if mt.Before(since) || mt.After(until) {
			continue
		}
		last := strings.LastIndex(k, "|")
		if last < 0 {
			continue
		}
		pre := k[:last]
		mid := strings.Index(pre, "|")
		if mid < 0 {
			continue
		}
		src := pre[:mid]
		dst := pre[mid+1:]
		var peer string
		if src == ip {
			peer = dst
		} else if dst == ip {
			peer = src
		} else {
			continue
		}
		mm := bins[peer]
		if mm == nil {
			mm = make(map[int64]minuteAcc)
			bins[peer] = mm
		}
		mm[mUnix] = minuteAcc{Bytes: mm[mUnix].Bytes + acc.Bytes, Packets: mm[mUnix].Packets + acc.Packets}
		totals[peer] += acc.Bytes
		if n, ok := store.pairMinuteSess.Get(k); ok {
			sessionTotals[peer] += n
		}
	}
	// Top peers by total bytes
	type item struct {
		Peer  string
		Bytes int64
	}
	arr := make([]item, 0, len(totals))
	for p, b := range totals {
		arr = append(arr, item{Peer: p, Bytes: b})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].Bytes == arr[j].Bytes {
			return arr[i].Peer < arr[j].Peer
		}
		return arr[i].Bytes > arr[j].Bytes
	})
	if limit > 0 && len(arr) > limit {
		arr = arr[:limit]
	}

	// Build series per top peer
	type point struct {
		Ts      string  `json:"ts"`
		Bytes   int64   `json:"bytes"`
		Packets int64   `json:"packets"`
		Bps     float64 `json:"bps"`
	}
	type series struct {
		Peer        string  `json:"peer"`
		PeerCountry string  `json:"peer_country"`
		TotalBytes  int64   `json:"total_bytes"`
		Sessions    int64   `json:"sessions"`
		Points      []point `json:"points"`
	}
	out := make([]series, 0, len(arr))
	for _, it := range arr {
		mm := bins[it.Peer]
		var pts []point
		for t := startAligned; !t.After(until); t = t.Add(step) {
			end := t.Add(step)
			var b, pk int64
			for mt := t.Truncate(time.Minute); mt.Before(end); mt = mt.Add(time.Minute) {
				mUnix := minuteBucketUnix(mt)
				if a, ok := mm[mUnix]; ok {
					b += a.Bytes
					pk += a.Packets
				}
			}
			bps := float64(b*8) / float64(stepSec)
			pts = append(pts, point{Ts: t.UTC().Format(time.RFC3339), Bytes: b, Packets: pk, Bps: bps})
		}
		sess := sessionTotals[it.Peer]
		out = append(out, series{Peer: it.Peer, PeerCountry: countryForIP(it.Peer), TotalBytes: it.Bytes, Sessions: sess, Points: pts})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ip":     ip,
		"since":  startAligned.UTC().Format(time.RFC3339),
		"until":  until.UTC().Format(time.RFC3339),
		"step":   stepSec,
		"series": out,
	})
}

// ipsHandler returns a list of known IPs, optionally filtered by substring 'q'.
func ipsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	set := make(map[string]struct{})
	for k := range store.ipMinuteTx.Items() {
		ip := k[:strings.LastIndex(k, "|")]
		set[ip] = struct{}{}
	}
	for k := range store.ipMinuteRx.Items() {
		ip := k[:strings.LastIndex(k, "|")]
		set[ip] = struct{}{}
	}
	for ip := range store.srcMap.Items() {
		set[ip] = struct{}{}
	}
	var arr []string
	for ip := range set {
		if q == "" || strings.Contains(strings.ToLower(ip), q) {
			arr = append(arr, ip)
		}
	}
	sort.Strings(arr)
	if limit > 0 && len(arr) > limit {
		arr = arr[:limit]
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ips": arr})
}

// simpleIndexHandler serves a minimal UI focused on two features:
// 1) Top N IP traffic in Mbit/s as a time series chart.
// 2) Search an IP and display a single TOTAL (tx+rx) line for that IP together with its top N peers in the same chart.

// ipInLoggingPrefixes returns true if ip is within the TSDB logging prefix list (if configured).
func ipInLoggingPrefixes(ipStr string) bool {
	// Prefer global UI filter if configured; otherwise, fall back to TSDB's filter list.
	active := uiFilterCIDRs
	if len(active) == 0 && tsdb != nil {
		active = tsdb.filterCIDRs
	}
	if len(active) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	for _, n := range active {
		if n.Contains(v4) {
			return true
		}
	}
	return false
}

// ipTableHandler exposes per-IP totals for 15m, 1h, 8h using minute summaries, filtered by logging prefix list.
func ipTableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// sort_window controls ordering: 15m, 1h, 8h (default 1h)
	sortWindow := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("sort_window")))
	if sortWindow == "" {
		sortWindow = "1h"
	}
	now := time.Now().UTC().Truncate(time.Minute)
	cut15 := now.Add(-15 * time.Minute).Unix()
	cut1h := now.Add(-1 * time.Hour).Unix()
	cut8h := now.Add(-8 * time.Hour).Unix()

	type agg struct{ Tx15, Rx15, Tx1h, Rx1h, Tx8h, Rx8h int64 }
	acc := make(map[string]*agg)

	// Build totals from per-IP minute aggregates (far fewer keys than per-pair),
	// counting TX for src IP and RX for dst IP. Respect logging CIDR filter using a memoized cache.
	allowedCache := make(map[string]bool)
	addFrom := func(isTx bool, m cmap.ConcurrentMap[string, minuteAcc]) {
		for k, v := range m.Items() {
			mu, ok := minuteFromKey(k)
			if !ok || mu < cut8h {
				continue
			}
			// key format: IP|unixMinute
			idx := strings.LastIndex(k, "|")
			if idx <= 0 {
				continue
			}
			ip := k[:idx]
			allowed, okc := allowedCache[ip]
			if !okc {
				allowed = ipInLoggingPrefixes(ip)
				allowedCache[ip] = allowed
			}
			if !allowed {
				continue
			}
			a := acc[ip]
			if a == nil {
				a = &agg{}
				acc[ip] = a
			}
			if isTx {
				a.Tx8h += v.Bytes
				if mu >= cut1h {
					a.Tx1h += v.Bytes
				}
				if mu >= cut15 {
					a.Tx15 += v.Bytes
				}
			} else {
				a.Rx8h += v.Bytes
				if mu >= cut1h {
					a.Rx1h += v.Bytes
				}
				if mu >= cut15 {
					a.Rx15 += v.Bytes
				}
			}
		}
	}
	addFrom(true, store.ipMinuteTx)
	addFrom(false, store.ipMinuteRx)

	type row struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		Tx15m   int64  `json:"tx_15m"`
		Rx15m   int64  `json:"rx_15m"`
		Tot15m  int64  `json:"total_15m"`
		Tx1h    int64  `json:"tx_1h"`
		Rx1h    int64  `json:"rx_1h"`
		Tot1h   int64  `json:"total_1h"`
		Tx8h    int64  `json:"tx_8h"`
		Rx8h    int64  `json:"rx_8h"`
		Tot8h   int64  `json:"total_8h"`
	}
	rows := make([]row, 0, len(acc))
	for ip, a := range acc {
		rows = append(rows, row{
			IP:      ip,
			Country: countryForIP(ip),
			Tx15m:   a.Tx15, Rx15m: a.Rx15, Tot15m: a.Tx15 + a.Rx15,
			Tx1h: a.Tx1h, Rx1h: a.Rx1h, Tot1h: a.Tx1h + a.Rx1h,
			Tx8h: a.Tx8h, Rx8h: a.Rx8h, Tot8h: a.Tx8h + a.Rx8h,
		})
	}
	// sort by selected window total desc, then IP asc
	value := func(r row) int64 {
		switch sortWindow {
		case "15m":
			return r.Tot15m
		case "8h":
			return r.Tot8h
		default:
			return r.Tot1h
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		vi, vj := value(rows[i]), value(rows[j])
		if vi == vj {
			return rows[i].IP < rows[j].IP
		}
		return vi > vj
	})

	// compute total sessions within selected window using pre-aggregated per-minute session counts
	var winStart time.Time
	switch sortWindow {
	case "15m":
		winStart = now.Add(-15 * time.Minute)
	case "8h":
		winStart = now.Add(-8 * time.Hour)
	default:
		winStart = now.Add(-1 * time.Hour)
	}
	var sessionsTotal int64
	winCutUnix := winStart.UTC().Truncate(time.Minute).Unix()
	for k, cnt := range store.pairMinuteSess.Items() {
		mUnix, ok := minuteFromKey(k)
		if !ok || mUnix < winCutUnix {
			continue
		}
		// key format: SRC|DST|unixMinute
		last := strings.LastIndex(k, "|")
		if last <= 0 {
			continue
		}
		rest := k[:last]
		first := strings.Index(rest, "|")
		if first <= 0 {
			continue
		}
		src := rest[:first]
		dst := rest[first+1:]
		// reuse allowedCache from above to avoid repeated CIDR checks
		allowedSrc, okS := allowedCache[src]
		if !okS {
			allowedSrc = ipInLoggingPrefixes(src)
			allowedCache[src] = allowedSrc
		}
		if !allowedSrc {
			allowedDst, okD := allowedCache[dst]
			if !okD {
				allowedDst = ipInLoggingPrefixes(dst)
				allowedCache[dst] = allowedDst
			}
			if !allowedDst {
				continue
			}
		}
		sessionsTotal += cnt
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"generated_at":   now.UTC().Format(time.RFC3339),
		"sessions_total": sessionsTotal,
		"rows":           rows,
	})
}

// ipTableIndexHandler serves a minimal HTML page with a table (no graphs), ordered by traffic.
func ipTableIndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>FlowAnalyzer - IP Traffic Table</title>
<style>
 body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0b1020;color:#e6edf3}
 header{padding:1rem 1.25rem;border-bottom:1px solid #22283d;display:flex;gap:.75rem;align-items:center;flex-wrap:wrap}
 header h1{font-size:1rem;margin:0;color:#cbd4e6}
 .container{padding:1rem 1.25rem}
 table{width:99%;border-collapse:collapse;background:#141a2f;border:1px solid #22283d;border-radius:10px;overflow:hidden}
 th,td{padding:.5rem .6rem;border-bottom:1px solid #22283d;text-align:right}
 th:first-child, td:first-child{text-align:left}
 tbody tr:hover{background:#10162b}
 small.m{color:#8b96b1}
 select,button{background:#0f1529;color:#e6edf3;border:1px solid #253055;border-radius:6px;padding:.35rem .5rem}
 .muted{color:#8b96b1}
 .panel{margin-top:1rem}
</style>
</head>
<body>
<header>
  <h1>FlowAnalyzer</h1>
  <div class="controls">
    <label>Order by
      <select id="sort">
        <option value="15m">Last 15m</option>
        <option value="1h" selected>Last 1h</option>
        <option value="8h">Last 8h</option>
      </select>
    </label>
    <button id="refresh">Refresh</button>
    <button id="badIpsBtn" title="View IPs that probed without response" onclick="window.location.href='/bad-ips'">Bad IPs</button>
    <small class="m">Only IPs within logging prefix list are shown.</small>
    <small class="m" id="sessInfo" style="margin-left:1rem">Total sessions: <span id="sessionsTotal">-</span></small>
  </div>
</header>
<div class="container">
  <table id="tbl">
    <thead>
      <tr>
        <th>IP</th>
        <th>CC</th>
        <th>TX 15m</th><th>RX 15m</th><th>Total 15m</th>
        <th>TX 1h</th><th>RX 1h</th><th>Total 1h</th>
        <th>TX 8h</th><th>RX 8h</th><th>Total 8h</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>

  <div id="peersPanel" class="panel" style="display:none">
    <h3>Peers for <span id="selIp"></span> (<span id="windowLabel"></span>) <button id="closePeers">Close</button></h3>
    <table id="peersTbl">
      <thead>
        <tr>
          <th>Peer IP</th>
          <th>Country</th>
          <th>Total</th>
          <th>Sessions</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    <small class="muted">Traffic is combined to/from the selected IP for the chosen window.</small>
  </div>

  <div id="logPanel" class="panel" style="display:none">
    <h3>Log search for <input id="logIp" style="width:180px"/> <button id="runLogSearch">Search</button> <button id="closeLog">Close</button></h3>
    <div class="controls" style="margin:.5rem 0">
      <label>From <input id="logFrom" type="datetime-local" step="1" style="width:220px"/></label>
      <label>To <input id="logTo" type="datetime-local" step="1" style="width:220px"/></label>
      <label>Side
        <select id="logSide">
          <option value="both" selected>both</option>
          <option value="src">src</option>
          <option value="dst">dst</option>
        </select>
      </label>
      <label>Src <input id="logSrc" style="width:140px"/></label>
      <label>Dst <input id="logDst" style="width:140px"/></label>
      <label>Proto <input id="logProto" style="width:80px"/></label>
      <label>Port <input id="logPort" style="width:80px"/></label>
    </div>
    <div class="muted">Defaults to last hour if From/To are empty. Max 10,000 rows per page.</div>
    <table id="logTbl">
      <thead>
        <tr>
          <th>Side</th>
          <th>Start</th>
          <th>End</th>
          <th>Proto</th>
          <th>Src</th>
          <th>Dst</th>
          <th>Bytes</th>
          <th>Pkts</th>
          <th>Router</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    <div class="controls" style="margin-top:.5rem">
      <button id="logPrev">Prev</button>
      <span class="muted">Page <span id="logPage">1</span></span>
      <button id="logNext">Next 10000</button>
    </div>
  </div>
</div>
<script>
function fmtBytes(n){
  const units=['B','KB','MB','GB','TB']; let i=0; let x=n; while(x>=1024 && i<units.length-1){ x/=1024; i++; }
  return (x>=100?x.toFixed(0):x>=10?x.toFixed(1):x.toFixed(2))+' '+units[i];
}
function getParam(name){ try{ return new URLSearchParams(location.search).get(name); }catch(e){ return null; } }
function setParam(name, value){ try{ const u=new URL(location.href); u.searchParams.set(name, value); history.pushState({}, '', u); }catch(e){} }
function delParam(name){ try{ const u=new URL(location.href); u.searchParams.delete(name); history.pushState({}, '', u); }catch(e){} }
function hidePeers(){ document.getElementById('peersPanel').style.display='none'; document.getElementById('selIp').textContent=''; document.getElementById('tbl').style.display=''; }
function windowSeconds(val){ if(val==='15m') return 15*60; if(val==='8h') return 8*3600; return 3600; }
async function loadPeers(ip){
  const sort=document.getElementById('sort').value;
  const seconds=windowSeconds(sort);
  const until=Math.floor(Date.now()/1000);
  const since=until-seconds;
  const url='/api/ip/peers?ip='+encodeURIComponent(ip)+'&since='+since+'&until='+until+'&step=300&limit=100';
  const r=await fetch(url);
  if(!r.ok){ console.error('peers http', r.status); return; }
  const data=await r.json();
  const tbody=document.querySelector('#peersTbl tbody');
  tbody.innerHTML='';
  (data.series||[]).forEach(function(s){
    const tr=document.createElement('tr');
    function td(t){ const d=document.createElement('td'); d.textContent=t; return d; }
    tr.appendChild(td(s.peer));
    tr.appendChild(td(s.peer_country || ''));
    tr.appendChild(td(fmtBytes(s.total_bytes))); 
    tr.appendChild(td(s.sessions!=null?s.sessions:0));
    tbody.appendChild(tr);
  });
  document.getElementById('selIp').textContent=ip;
  document.getElementById('windowLabel').textContent=sort;
  document.getElementById('peersPanel').style.display='';
  document.getElementById('tbl').style.display='none';
}
async function load(){
  const sort=document.getElementById('sort').value;
  const r=await fetch('/api/ip_table?sort_window='+encodeURIComponent(sort));
  if(!r.ok){ throw new Error('http '+r.status); }
  const data=await r.json();
  if(document.getElementById('sessionsTotal')){
    document.getElementById('sessionsTotal').textContent = (data.sessions_total!=null?data.sessions_total:'-');
  }
  const tbody=document.querySelector('#tbl tbody');
  tbody.innerHTML='';
  (data.rows||[]).forEach(function(it){
    const tr=document.createElement('tr');
    function td(t){ const d=document.createElement('td'); d.textContent=t; return d; }
    const ipTd=document.createElement('td');
    const a=document.createElement('a'); a.href='#'; a.textContent=it.ip; a.addEventListener('click', function(e){ e.preventDefault(); const url='/logs?src='+encodeURIComponent(it.ip)+'&autoscroll=1'; window.open(url, '_blank'); });
    const peersBtn=document.createElement('button'); peersBtn.textContent='Peers'; peersBtn.style.marginLeft='.4rem'; peersBtn.addEventListener('click', function(e){ e.preventDefault(); setParam('ip', it.ip); loadPeers(it.ip); });
    const liveBtn=document.createElement('button'); liveBtn.textContent='Live Sessions'; liveBtn.style.marginLeft='.4rem'; liveBtn.addEventListener('click', function(e){ e.preventDefault(); const url='/live?ip='+encodeURIComponent(it.ip); window.open(url, '_blank'); });
    ipTd.appendChild(a);
    ipTd.appendChild(peersBtn);
    ipTd.appendChild(liveBtn);
    tr.appendChild(ipTd);
    tr.appendChild(td(it.country || ''));
    tr.appendChild(td(fmtBytes(it.tx_15m)));
    tr.appendChild(td(fmtBytes(it.rx_15m)));
    tr.appendChild(td(fmtBytes(it.total_15m)));
    tr.appendChild(td(fmtBytes(it.tx_1h)));
    tr.appendChild(td(fmtBytes(it.rx_1h)));
    tr.appendChild(td(fmtBytes(it.total_1h)));
    tr.appendChild(td(fmtBytes(it.tx_8h)));
    tr.appendChild(td(fmtBytes(it.rx_8h)));
    tr.appendChild(td(fmtBytes(it.total_8h)));
    tbody.appendChild(tr);
  });
}
function initFromURL(){
  const sortParam=getParam('sort');
  if(sortParam==='15m'||sortParam==='1h'||sortParam==='8h'){
    document.getElementById('sort').value=sortParam;
  }
  load();
  const ip=getParam('ip');
  if(ip){ loadPeers(ip); } else { hidePeers(); }
}
window.addEventListener('popstate', function(){
  const sortParam=getParam('sort');
  if(sortParam){ document.getElementById('sort').value=sortParam; }
  load();
  const ip=getParam('ip');
  if(ip){ loadPeers(ip); } else { hidePeers(); }
});
document.getElementById('refresh').addEventListener('click', function(){
  load();
  const ip=getParam('ip'); if(ip){ loadPeers(ip); }
});
document.getElementById('sort').addEventListener('change', function(){
  const sort=this.value;
  setParam('sort', sort);
  load();
  const ip=getParam('ip'); if(ip){ loadPeers(ip); }
});
document.getElementById('closePeers').addEventListener('click', function(){
  delParam('ip');
  hidePeers();
});

// Log Search integration
let logPage = 1;
let logHasMore = false;
function hideLog(){ document.getElementById('logPanel').style.display='none'; }
function showLogFor(ip){
  hidePeers();
  const el = document.getElementById('logIp');
  if(el){ el.value = ip; }
  document.getElementById('logPanel').style.display='';
  logPage = 1;
  document.getElementById('logPage').textContent = '1';
  runLogSearch();
}
function ensureDefaultRange(){
  const f=document.getElementById('logFrom');
  const t=document.getElementById('logTo');
  if(f && t && !f.value && !t.value){
    function pad(n){ return String(n).padStart(2,'0'); }
    function toLocal(d){ return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds()); }
    const now=new Date();
    const hourAgo=new Date(now.getTime()-3600*1000);
    f.value=toLocal(hourAgo);
    t.value=toLocal(now);
  }
}
function buildLogURL(){
  const ip=(document.getElementById('logIp').value||'').trim();
  const since=(document.getElementById('logFrom').value||'').trim();
  const until=(document.getElementById('logTo').value||'').trim();
  const side=document.getElementById('logSide').value;
  const src=(document.getElementById('logSrc').value||'').trim();
  const dst=(document.getElementById('logDst').value||'').trim();
  const proto=(document.getElementById('logProto').value||'').trim();
  const port=(document.getElementById('logPort').value||'').trim();
  const p=new URLSearchParams();
  p.set('ip', ip);
  if(since) p.set('since', since);
  if(until) p.set('until', until);
  if(side && side!=='both') p.set('side', side);
  if(src) p.set('src', src);
  if(dst) p.set('dst', dst);
  if(proto) p.set('protocol', proto);
  if(port) p.set('port', port);
  p.set('page', String(logPage));
  p.set('page_size', '10000');
  return '/api/logs/search?'+p.toString();
}
async function runLogSearch(){
  const ip=(document.getElementById('logIp').value||'').trim();
  if(!ip){ return; }
  ensureDefaultRange();
  document.getElementById('logPage').textContent = String(logPage);
  const r=await fetch(buildLogURL());
  if(!r.ok){ console.error('log search http', r.status); return; }
  const data=await r.json();
  logHasMore = !!data.has_more;
  renderLogItems(data.items||[]);
  document.getElementById('logNext').disabled = !logHasMore;
  document.getElementById('logPrev').disabled = logPage<=1;
}
function renderLogItems(items){
  const tbody=document.querySelector('#logTbl tbody');
  tbody.innerHTML='';
  items.forEach(function(it){
    const tr=document.createElement('tr');
    function td(t){ const d=document.createElement('td'); d.textContent=t; return d; }
    tr.appendChild(td(it.side||''));
    tr.appendChild(td(it.start||''));
    tr.appendChild(td(it.end||''));
    tr.appendChild(td(it.protocol||''));
    tr.appendChild(td((it.src_ip||'') + (it.src_port?(':'+it.src_port):'')));
    tr.appendChild(td((it.dst_ip||'') + (it.dst_port?(':'+it.dst_port):'')));
    tr.appendChild(td(String(it.bytes||0)));
    tr.appendChild(td(String(it.packets||0)));
    tr.appendChild(td(it.router||''));
    tbody.appendChild(tr);
  });
}

document.getElementById('runLogSearch').addEventListener('click', function(){ logPage=1; runLogSearch(); });

document.getElementById('closeLog').addEventListener('click', function(){ hideLog(); });

document.getElementById('logNext').addEventListener('click', function(){ if(logHasMore){ logPage++; runLogSearch(); } });

document.getElementById('logPrev').addEventListener('click', function(){ if(logPage>1){ logPage--; runLogSearch(); } });

initFromURL();
setInterval(function(){
  load();
  const ip=getParam('ip'); if(ip){ loadPeers(ip); }
}, 15000);
</script>
</body>
</html>`))
}

// EnqueueOpenMany writes heartbeat/open-session entries (may have zero bytes/packets).
func (t *tsdbWriter) EnqueueOpenMany(sessions []FlowSession) {
	if t == nil || !t.enabled {
		return
	}
	for i := range sessions {
		s := sessions[i]
		// src side
		if p, line, ok := t.buildPathAndLine(true, s); ok {
			sh := t.shardFor(p)
			select {
			case t.queues[sh] <- tsdbItem{path: p, line: line}:
			default:
				atomic.AddUint64(&t.dropped, 1)
			}
		}
		// dst side
		if p, line, ok := t.buildPathAndLine(false, s); ok {
			sh := t.shardFor(p)
			select {
			case t.queues[sh] <- tsdbItem{path: p, line: line}:
			default:
				atomic.AddUint64(&t.dropped, 1)
			}
		}
	}
}

// collapseLogItems merges duplicate log items representing the same session across routers.
func collapseLogItems(items []fsLogItem) []fsLogItem {
	if len(items) <= 1 {
		return items
	}
	type key struct {
		Side     string
		Start    string
		End      string
		Protocol string
		SrcIP    string
		SrcPort  int
		DstIP    string
		DstPort  int
	}
	idxMap := make(map[key]int, len(items))
	out := make([]fsLogItem, 0, len(items))
	for _, it := range items {
		k := key{
			Side:     strings.TrimSpace(it.Side),
			Start:    it.Start,
			End:      it.End,
			Protocol: strings.ToUpper(strings.TrimSpace(it.Protocol)),
			SrcIP:    it.SrcIP,
			SrcPort:  it.SrcPort,
			DstIP:    it.DstIP,
			DstPort:  it.DstPort,
		}
		if i, ok := idxMap[k]; ok {
			cur := &out[i]
			// Merge routers unique
			routers := make([]string, 0, 4)
			if strings.TrimSpace(cur.Router) != "" {
				for _, r := range strings.Split(cur.Router, ",") {
					routers = appendUniqueRouter(routers, strings.TrimSpace(r))
				}
			}
			if strings.TrimSpace(it.Router) != "" {
				for _, r := range strings.Split(it.Router, ",") {
					routers = appendUniqueRouter(routers, strings.TrimSpace(r))
				}
			}
			cur.Router = strings.Join(routers, ",")
			if it.Bytes > cur.Bytes {
				cur.Bytes = it.Bytes
			}
			if it.Packets > cur.Packets {
				cur.Packets = it.Packets
			}
			// keep Start/End of first occurrence for stability
			continue
		}
		it.Router = strings.TrimSpace(it.Router)
		out = append(out, it)
		idxMap[k] = len(out) - 1
	}
	return out
}

// liveSessionsPageHandler serves a dedicated page for real-time session view with filters similar to /logs.
func liveSessionsPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>FlowAnalyzer - Live Sessions</title>
<style>
 body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0b1020;color:#e6edf3}
 header, .controls{padding:1rem 1.25rem;border-bottom:1px solid #22283d;display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
 table{width:99%;border-collapse:collapse;background:#141a2f;border:1px solid #22283d;border-radius:10px;margin:1rem;overflow:hidden}
 th,td{padding:.4rem .5rem;border-bottom:1px solid #22283d;text-align:right}
 th:first-child, td:first-child{text-align:left}
 small.m{color:#8b96b1}
 select,input,button{background:#0f1529;color:#e6edf3;border:1px solid #253055;border-radius:6px;padding:.35rem .5rem}
 .muted{color:#8b96b1}
 .nowrap{white-space:nowrap}
</style>
</head>
<body>
<header><h1 style="font-size:1rem;margin:0;color:#cbd4e6">Live Sessions</h1><small class="m">Real-time view</small></header>
<div id="controls" class="controls">
  <label>IP <input id="fIP" style="width:160px" placeholder="optional"/></label>
  <label>Side <select id="fSide"><option value="both" selected>both</option><option value="src">src</option><option value="dst">dst</option></select></label>
  <label>Src <input id="fSrc" style="width:160px"/></label>
  <label>Dst <input id="fDst" style="width:160px"/></label>
  <label>Proto <input id="fProto" style="width:80px"/></label>
  <label>Port <input id="fPort" style="width:80px"/></label>
  <button id="apply">Apply</button>
</div>
<div class="muted" style="padding:0 1.25rem;">Rows appear as sessions are observed. They update live and are removed when sessions end.</div>
<table id="sessTbl"><thead><tr>
  <th class="nowrap">Start</th><th class="nowrap">Last</th><th>Proto</th><th>Src</th><th>Dst</th><th>Bytes</th><th>Pkts</th><th>Router</th>
</tr></thead><tbody></tbody></table>
<script>
(function(){
  function qs(name){ try{ return new URLSearchParams(location.search).get(name)||''; }catch(e){ return ''; } }
  function buildWSURL(){ const p=new URLSearchParams(); const ip=(document.getElementById('fIP').value||'').trim(); const side=document.getElementById('fSide').value; const src=(document.getElementById('fSrc').value||'').trim(); const dst=(document.getElementById('fDst').value||'').trim(); const proto=(document.getElementById('fProto').value||'').trim(); const port=(document.getElementById('fPort').value||'').trim(); if(ip) p.set('ip', ip); if(side && side!=='both') p.set('side', side); if(src) p.set('src', src); if(dst) p.set('dst', dst); if(proto) p.set('protocol', proto); if(port) p.set('port', port); const wsProto=(location.protocol==='https:')?'wss':'ws'; return wsProto+'://'+location.host+'/ws/sessions?'+p.toString(); }
  function td(t){ const d=document.createElement('td'); d.textContent=t; return d; }
  const tbody = document.querySelector('#sessTbl tbody');
  const rows = new Map(); // key -> {tr, bytes, packets}
  const ttlMs = 180000; // safety: remove stale rows after 3 minutes without updates
  function fmtAddr(ip, port){ return ip + (port?(':'+port):''); }
  function mergeRouters(a, b){
    const s = new Set();
    (String(a||'').split(',')).forEach(r=>{ r=r.trim(); if(r) s.add(r); });
    (String(b||'').split(',')).forEach(r=>{ r=r.trim(); if(r) s.add(r); });
    return Array.from(s).join(',');
  }
  function onAdd(ev){
    const k=ev.key; const s=ev.session||{}; let row=rows.get(k);
    if(!row){
      const tr=document.createElement('tr'); tr.dataset.key=k;
      tr.appendChild(td(s.start||'')); tr.appendChild(td(s.last||'')); tr.appendChild(td(s.protocol||''));
      tr.appendChild(td(fmtAddr(s.src_ip||'', s.src_port||0))); tr.appendChild(td(fmtAddr(s.dst_ip||'', s.dst_port||0)));
      tr.appendChild(td(String(s.bytes||0))); tr.appendChild(td(String(s.packets||0))); tr.appendChild(td(s.router||''));
      tbody.appendChild(tr);
      row={tr:tr, bytes:(s.bytes||0), packets:(s.packets||0)}; rows.set(k,row);
    } else {
      row.bytes += (s.bytes||0); row.packets += (s.packets||0);
      const tds=row.tr.children;
      if(tds&&tds.length>=8){
        // update Last
        tds[1].textContent = s.last||tds[1].textContent;
        // earliest Start
        if(s.start){ const cur=Date.parse(tds[0].textContent||''); const inc=Date.parse(s.start); if(!isNaN(inc) && (isNaN(cur) || inc < cur)){ tds[0].textContent = s.start; } }
        // merge routers
        tds[7].textContent = mergeRouters(tds[7].textContent, s.router||'');
        // totals
        tds[5].textContent = String(row.bytes); tds[6].textContent = String(row.packets);
      }
    }
  }
  function onEnd(ev){ const k=ev.key; const row=rows.get(k); if(row){ row.tr.remove(); rows.delete(k); } }
  function sweepStale(){
    const now=Date.now();
    rows.forEach((row,k)=>{
      const tds=row.tr.children; if(!tds||tds.length<8) return;
      const last=Date.parse(tds[1].textContent||'');
      if(!isNaN(last) && now-last>ttlMs){ row.tr.remove(); rows.delete(k); }
    });
  }
  setInterval(sweepStale, 30000);
  let ws=null; function openWS(){ try{ if(ws){ ws.close(); } // reset state
    rows.forEach((v)=>v.tr.remove()); rows.clear();
    const url = buildWSURL(); ws = new WebSocket(url); ws.onmessage=function(e){ try{ const ev=JSON.parse(e.data); if(ev && ev.event==='add'){ onAdd(ev); } else if(ev && ev.event==='end'){ onEnd(ev); } }catch(err){} };
    ws.onopen=function(){}; ws.onerror=function(){}; ws.onclose=function(){};
  }catch(e){} }
  function init(){ document.getElementById('fIP').value = qs('ip')||qs('src')||''; document.getElementById('fSrc').value = qs('src')||''; document.getElementById('fDst').value = qs('dst')||''; document.getElementById('fProto').value = qs('protocol')||qs('proto')||''; document.getElementById('fPort').value = qs('port')||''; const side=qs('side'); if(side){ const el=document.getElementById('fSide'); for(let i=0;i<el.options.length;i++){ if(el.options[i].value===side){ el.selectedIndex=i; break; } } } openWS(); }
  window.addEventListener('DOMContentLoaded', function(){ document.getElementById('apply').addEventListener('click', openWS); ['fIP','fSide','fSrc','fDst','fProto','fPort'].forEach(function(id){ const el=document.getElementById(id); if(el){ el.addEventListener('change', openWS); } }); init(); });
})();
</script>
</body>
</html>`))
}

// badIPsAPIHandler returns a list of source IPs that attempted to access destinations within
// the logging prefixes but did not receive any response back, ordered by the number of unique
// destination IPs they probed without response. Time window defaults to last 1 hour and is
// adjustable via since/until query params (RFC3339 or relative like -1h).
func badIPsAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	var since, until time.Time
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		if t, ok := parseTime(v); ok {
			since = t
		}
	}
	if v := strings.TrimSpace(q.Get("until")); v != "" {
		if t, ok := parseTime(v); ok {
			until = t
		}
	}
	if until.IsZero() {
		until = time.Now()
	}
	if since.IsZero() {
		since = until.Add(-1 * time.Hour)
	}
	if until.Before(since) {
		since, until = until, since
	}
	limit := 100
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	// Build a set of pair keys for existence checks and iterate pairs in the time window.
	pairs := store.pairMinute.Items() // key format: SRC|DST|unix5m
	keyExists := make(map[string]struct{}, len(pairs))
	for k := range pairs {
		keyExists[k] = struct{}{}
	}

	// For each SRC->DST record in window, if no reverse DST->SRC traffic exists in same/adjacent bucket,
	// consider it an unanswered attempt. We will compute both:
	//  - distinct destination IP count per source
	//  - total unanswered attempts per source (sum of sessions for the pair-minute)
	tStart := since.UTC().Truncate(5 * time.Minute)
	tEnd := until.UTC()
	perSrcDistinct := make(map[string]map[string]struct{}) // src -> set(dst)
	perSrcAttempts := make(map[string]int)
	lastSeen := make(map[string]time.Time)
	// Respect UI/TSDB CIDR filter: only count attempts targeting destinations within the active CIDRs ("current view").
	allowedCache := make(map[string]bool)
	isAllowed := func(ip string) bool {
		if v, ok := allowedCache[ip]; ok {
			return v
		}
		v := ipInLoggingPrefixes(ip)
		allowedCache[ip] = v
		return v
	}
	for k := range pairs {
		// parse key
		last := strings.LastIndex(k, "|")
		if last <= 0 || last+1 >= len(k) {
			continue
		}
		muStr := k[last+1:]
		rest := k[:last]
		first := strings.Index(rest, "|")
		if first <= 0 {
			continue
		}
		src := rest[:first]
		dst := rest[first+1:]
		// Only consider destinations within the active CIDR filter to match the current view
		if !isAllowed(dst) {
			continue
		}
		mu, err := strconv.ParseInt(muStr, 10, 64)
		if err != nil {
			continue
		}
		mt := time.Unix(mu, 0).UTC()
		if mt.Before(tStart) || mt.After(tEnd) {
			continue
		}
		// reverse existence in same or adjacent bucket (+/- 5m)
		m0 := mu
		m1 := mu - int64(5*60)
		m2 := mu + int64(5*60)
		rev0 := fmt.Sprintf("%s|%s|%d", dst, src, m0)
		rev1 := fmt.Sprintf("%s|%s|%d", dst, src, m1)
		rev2 := fmt.Sprintf("%s|%s|%d", dst, src, m2)
		if _, ok := keyExists[rev0]; ok {
			continue
		}
		if _, ok := keyExists[rev1]; ok {
			continue
		}
		if _, ok := keyExists[rev2]; ok {
			continue
		}
		// unanswered
		set := perSrcDistinct[src]
		if set == nil {
			set = make(map[string]struct{})
			perSrcDistinct[src] = set
		}
		set[dst] = struct{}{}
		// attempts: use session count if available; fallback 1
		if n, ok := store.pairMinuteSess.Get(k); ok {
			perSrcAttempts[src] += int(n)
		} else {
			perSrcAttempts[src] += 1
		}
		if lastSeen[src].Before(mt) {
			lastSeen[src] = mt
		}
	}

	type row struct {
		IP       string `json:"ip"`
		Country  string `json:"country"`
		Count    int    `json:"count"`    // distinct destinations (backward compatibility)
		Attempts int    `json:"attempts"` // total unanswered attempts
		LastSeen string `json:"last_seen"`
	}
	var rows []row
	for src, set := range perSrcDistinct {
		rows = append(rows, row{
			IP:       src,
			Country:  countryForIP(src),
			Count:    len(set),
			Attempts: perSrcAttempts[src],
			LastSeen: lastSeen[src].UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		// Order by total unanswered attempts (desc), then distinct dest count (desc),
		// then last_seen (desc), then IP (asc) for stability.
		if rows[i].Attempts == rows[j].Attempts {
			if rows[i].Count == rows[j].Count {
				if rows[i].LastSeen == rows[j].LastSeen {
					return rows[i].IP < rows[j].IP
				}
				return rows[i].LastSeen > rows[j].LastSeen
			}
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Attempts > rows[j].Attempts
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"since":        tStart.Format(time.RFC3339),
		"until":        tEnd.UTC().Format(time.RFC3339),
		"items":        rows,
	})
}

// badIPsPageHandler serves a simple table UI for the bad IPs list.
func badIPsPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>FlowAnalyzer - Unanswered Access Attempts</title>
<style>
 body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0b1020;color:#e6edf3}
 header{padding:1rem 1.25rem;border-bottom:1px solid #22283d;display:flex;gap:.75rem;align-items:center;flex-wrap:wrap}
 header h1{font-size:1rem;margin:0;color:#cbd4e6}
 .container{padding:1rem 1.25rem}
 table{width:99%;border-collapse:collapse;background:#141a2f;border:1px solid #22283d;border-radius:10px;overflow:hidden}
 th,td{padding:.5rem .6rem;border-bottom:1px solid #22283d;text-align:right}
 th:first-child, td:first-child{text-align:left}
 tbody tr:hover{background:#10162b}
 small.m{color:#8b96b1}
 select,button{background:#0f1529;color:#e6edf3;border:1px solid #253055;border-radius:6px;padding:.35rem .5rem}
 .muted{color:#8b96b1}
</style>
</head>
<body>
<header>
  <h1>Unanswered Access Attempts</h1>
  <div class="controls">
    <label>Window
      <select id="win">
        <option value="1h" selected>Last 1h</option>
        <option value="8h">Last 8h</option>
        <option value="24h">Last 24h</option>
      </select>
    </label>
    <button id="refresh">Refresh</button>
    <small class="m">Shows distinct destination IPs scanned and total unanswered attempts (no reverse traffic) within the selected window.</small>
  </div>
</header>
<div class="container">
  <table id="tbl">
    <thead>
      <tr>
        <th>Source IP</th>
        <th>Country</th>
        <th>Unanswered Dests</th>
        <th>Total Attempts</th>
        <th>Last Seen</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>
</div>
<script>
function buildURL(){
  const w=document.getElementById('win').value;
  let since='';
  const now=new Date();
  if(w==='1h'){ since=new Date(now.getTime()-3600*1000); }
  else if(w==='8h'){ since=new Date(now.getTime()-8*3600*1000); }
  else { since=new Date(now.getTime()-24*3600*1000); }
  function pad(n){return String(n).padStart(2,'0');}
  function toLocal(d){return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds());}
  const p=new URLSearchParams();
  p.set('since', toLocal(since));
  p.set('until', toLocal(now));
  p.set('limit','200');
  return '/api/bad-ips?'+p.toString();
}
function render(items){
  const tbody=document.querySelector('#tbl tbody');
  tbody.innerHTML='';
  (items||[]).forEach(function(it){
    const tr=document.createElement('tr');
    function td(t){ const d=document.createElement('td'); d.textContent=t; return d; }
    const src=document.createElement('td');
    const a=document.createElement('a'); a.href='/logs?src='+encodeURIComponent(it.ip)+'&autoscroll=1'; a.textContent=it.ip; a.target='_blank'; src.appendChild(a);
    tr.appendChild(src);
    tr.appendChild(td(it.country||''));
    tr.appendChild(td(String(it.count||0)));
    tr.appendChild(td(String(it.attempts||0)));
    tr.appendChild(td(it.last_seen||''));
    const ac=document.createElement('td');
    const l1=document.createElement('a'); l1.href='/logs?src='+encodeURIComponent(it.ip); l1.textContent='Logs'; l1.target='_blank';
    ac.appendChild(l1);
    tr.appendChild(ac);
    tbody.appendChild(tr);
  });
}
async function load(){
  const r=await fetch(buildURL());
  if(!r.ok){ console.error('api', r.status); return; }
  const data=await r.json();
  render(data.items||[]);
}
window.addEventListener('DOMContentLoaded', function(){
  document.getElementById('refresh').addEventListener('click', load);
  document.getElementById('win').addEventListener('change', load);
  load();
});
</script>
</body>
</html>`))
}

// --- INI configuration loading -------------------------------------------------
// All configuration parameters can be specified in an INI-style file placed
// alongside the executable. We look for "FlowAnalyzer.ini" first, then
// fallback to "config.ini". Keys are case-insensitive and are matched against
// the same names used for environment variables (e.g., ADDR, PORT, TSDB_ROOT).

var iniConfig map[string]string

// getINI returns a value from the loaded INI by key (case-insensitive).
func getINI(k string) (string, bool) {
	if iniConfig == nil {
		return "", false
	}
	v, ok := iniConfig[strings.ToUpper(strings.TrimSpace(k))]
	return v, ok
}

// loadINIConfig parses the INI file located next to the executable.
func loadINIConfig() {
	// Determine executable directory.
	exe, err := os.Executable()
	dir := "."
	if err == nil && strings.TrimSpace(exe) != "" {
		dir = filepath.Dir(exe)
	}
	candidates := []string{
		filepath.Join(dir, "FlowAnalyzer.ini"),
		filepath.Join(dir, "config.ini"),
	}
	var path string
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			path = p
			break
		}
	}
	if path == "" {
		// No INI present -> generate one with current effective settings beside the executable.
		// Do not overwrite if the file suddenly appears between checks.
		outPath := filepath.Join(dir, "FlowAnalyzer.ini")

		// Build current effective configuration using environment variables or defaults.
		bool01 := func(b bool) string {
			if b {
				return "1"
			}
			return "0"
		}
		cfg := map[string]string{
			"ADDR":                    getenv("ADDR", "0.0.0.0"),
			"PORT":                    getenv("PORT", "8080"),
			"RETENTION_MINUTES":       strconv.Itoa(getenvInt("RETENTION_MINUTES", retentionMinutes)),
			"FLOW_TIMEOUT_MINUTES":    strconv.Itoa(getenvInt("FLOW_TIMEOUT_MINUTES", flowTimeoutMinutes)),
			"COMPACT_EVERY_SECONDS":   strconv.Itoa(getenvInt("COMPACT_EVERY_SECONDS", compactEverySeconds)),
			"MAX_SESSIONS_TRIGGER":    strconv.Itoa(getenvInt("MAX_SESSIONS_TRIGGER", maxSessionsBeforeCompactTrigger)),
			"METRICS_RETENTION_HOURS": strconv.Itoa(getenvInt("METRICS_RETENTION_HOURS", summariesRetentionHours)),
			"COLLECTOR_WORKERS":       strconv.Itoa(getenvInt("COLLECTOR_WORKERS", collectorWorkers)),
			"COLLECTOR_QUEUE":         strconv.Itoa(getenvInt("COLLECTOR_QUEUE", collectorQueue)),
			"WS_MAX_CONNS":            strconv.Itoa(getenvInt("WS_MAX_CONNS", wsMaxConns)),
			"PPROF_ENABLE":            bool01(getenvBool("PPROF_ENABLE", false)),
			"LOG_REQUESTS":            bool01(getenvBool("LOG_REQUESTS", false)),
			"SERVICE_DISABLE":         bool01(getenvBool("SERVICE_DISABLE", false)),
			"DEDUP_ENABLE":            bool01(getenvBool("DEDUP_ENABLE", true)),
			"DEDUP_TTL_MIN":           strconv.Itoa(getenvInt("DEDUP_TTL_MIN", 1)),
			"TSDB_ENABLE":             bool01(getenvBool("TSDB_ENABLE", true)),
			"TSDB_ROOT":               getenv("TSDB_ROOT", "E:\\DB"),
			"TSDB_SHARDS":             strconv.Itoa(getenvInt("TSDB_SHARDS", runtime.GOMAXPROCS(0))),
			"TSDB_QUEUE_SIZE":         strconv.Itoa(getenvInt("TSDB_QUEUE_SIZE", 65536)),
			"TSDB_FLUSH_MS":           strconv.Itoa(getenvInt("TSDB_FLUSH_MS", 1000)),
			"TSDB_IDLE_CLOSE_SEC":     strconv.Itoa(getenvInt("TSDB_IDLE_CLOSE_SEC", 60)),
			"TSDB_LOG_DROPS":          bool01(getenvBool("TSDB_LOG_DROPS", false)),
			"TSDB_LOG_ERRORS":         bool01(getenvBool("TSDB_LOG_ERRORS", true)),
			"TSDB_FILTER_CIDRS":       getenv("TSDB_FILTER_CIDRS", ""),
			"NETFLOW_ADDR":            getenv("NETFLOW_ADDR", "0.0.0.0:2055"),
			"IPFIX_ADDR":              getenv("IPFIX_ADDR", "0.0.0.0:4739"),
		}

		// Stable order for readability
		order := []string{
			"ADDR", "PORT",
			"PPROF_ENABLE", "LOG_REQUESTS", "SERVICE_DISABLE",
			"RETENTION_MINUTES", "FLOW_TIMEOUT_MINUTES", "COMPACT_EVERY_SECONDS", "MAX_SESSIONS_TRIGGER",
			"METRICS_RETENTION_HOURS",
			"COLLECTOR_WORKERS", "COLLECTOR_QUEUE",
			"WS_MAX_CONNS",
			"DEDUP_ENABLE", "DEDUP_TTL_MIN",
			"TSDB_ENABLE", "TSDB_ROOT", "TSDB_SHARDS", "TSDB_QUEUE_SIZE", "TSDB_FLUSH_MS", "TSDB_IDLE_CLOSE_SEC", "TSDB_LOG_DROPS", "TSDB_LOG_ERRORS", "TSDB_FILTER_CIDRS",
			"NETFLOW_ADDR", "IPFIX_ADDR",
		}

		var b strings.Builder
		b.WriteString("; FlowAnalyzer.ini\n")
		b.WriteString("; Auto-generated on ")
		b.WriteString(time.Now().Format(time.RFC3339))
		b.WriteString("\n; Place this file next to FlowAnalyzer.exe.\n")
		b.WriteString("; Environment variables, if set, override these values.\n")
		b.WriteString("; Boolean values use 1/0 (true/false).\n\n")
		for _, k := range order {
			if v, ok := cfg[k]; ok {
				b.WriteString(k)
				b.WriteString("=")
				b.WriteString(v)
				b.WriteString("\n")
			}
		}

		// Try to create the file (do not overwrite)
		if f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644); err == nil {
			_, _ = f.WriteString(b.String())
			_ = f.Close()
			// Reflect in-memory INI for this process too
			iniConfig = cfg
		}
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	cfg := make(map[string]string)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// skip section headers like [section]
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			continue
		}
		// support both key=value and key: value
		sepIdx := strings.IndexAny(line, "=:")
		if sepIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:sepIdx])
		val := strings.TrimSpace(line[sepIdx+1:])
		// remove optional surrounding quotes
		if len(val) >= 2 && ((strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) || (strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'"))) {
			val = val[1 : len(val)-1]
		}
		if key != "" {
			cfg[strings.ToUpper(key)] = val
		}
	}
	if err := s.Err(); err != nil {
		// ignore parse errors silently to avoid disrupting startup
	}
	iniConfig = cfg
}

func init() {
	loadINIConfig()
}

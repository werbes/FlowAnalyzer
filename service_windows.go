//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	svc "golang.org/x/sys/windows/svc"
)

func maybeRunService() bool {
	isSvc, err := svc.IsWindowsService()
	if err == nil && isSvc && !getenvBool("SERVICE_DISABLE", false) {
		if err := runService(); err != nil {
			log.Printf("service failed: %v", err)
		}
		return true
	}
	return false
}

// runService starts FlowAnalyzer as a Windows service. It mirrors the console startup path
// but integrates with the Windows Service Control Manager for stop/shutdown.
func runService() error {
	return svc.Run("FlowAnalyzer", &flowSvc{})
}

type flowSvc struct{}

func (f *flowSvc) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	// Build HTTP mux with all endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/ingest", ingestHandler)
	mux.HandleFunc("/api/sessions", sessionsHandler)
	mux.HandleFunc("/api/metrics/throughput", throughputHandler)
	mux.HandleFunc("/api/metrics/top", topHandler)
	mux.HandleFunc("/api/metrics/throughput_by_protocol_precomputed", throughputByProtocolPrecomputedHandler)
	mux.HandleFunc("/api/logs/search", logsSearchHandler)
	mux.HandleFunc("/api/top_ips", topIPsHandler)
	mux.HandleFunc("/api/ip/protocols", ipProtocolsHandler)
	mux.HandleFunc("/api/ip/peers", ipPeersHandler)
	mux.HandleFunc("/api/ips", ipsHandler)
	mux.HandleFunc("/api/ip", ipViewHandler)
	mux.HandleFunc("/api/ip_table", ipTableHandler)
	// New UI page for dedicated log search window
	mux.HandleFunc("/logs", logsPageHandler)
	// WebSocket endpoint for live log feed
	mux.HandleFunc("/ws/logs", wsLogsHandler)
	mux.HandleFunc("/", ipTableIndexHandler)

	var handler http.Handler = mux
	// enable gzip compression for supported clients in service mode
	handler = gzipMiddleware(handler)
	if getenvBool("LOG_REQUESTS", false) {
		handler = logRequests(handler)
	}

	addr := getenv("ADDR", "0.0.0.0")
	port := getenv("PORT", "8080")
	listen := fmt.Sprintf("%s:%s", addr, port)
	srv := &http.Server{Addr: listen, Handler: handler}

	// Background context for workers
	bgCtx, bgCancel := context.WithCancel(context.Background())

	// Start store maintenance
	store.StartMaintenance(bgCtx)

	// Configure cross-router dedup from environment
	dedupEnable = getenvBool("DEDUP_ENABLE", true)
	if ttlMin := getenvInt("DEDUP_TTL_MIN", 15); ttlMin > 0 {
		dedupTTL = time.Duration(ttlMin) * time.Minute
	}
	log.Printf("[svc] Dedup: enabled=%v ttl=%s", dedupEnable, dedupTTL.String())

	// Initialize filesystem TSDB (enabled by default)
	if getenvBool("TSDB_ENABLE", true) {
		root := getenv("TSDB_ROOT", "E:\\DB")
		if err := os.MkdirAll(root, 0o755); err != nil {
			fb := ".\\DB"
			log.Printf("[svc] TSDB: cannot use root %s (%v), falling back to %s", root, err, fb)
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
		if cidrs := getenv("TSDB_FILTER_CIDRS", ""); cidrs != "" {
			tsdb.filterCIDRs = parseCIDRList(cidrs)
			log.Printf("[svc] TSDB filter: %d CIDRs active", len(tsdb.filterCIDRs))
		}
		tsdb.Start(bgCtx)
		log.Printf("[svc] TSDB enabled: root=%s shards=%d queue=%d", root, shards, qsize)
	}

	// Always initialize UI filter from env regardless of TSDB_ENABLE
	if cidrs := getenv("TSDB_FILTER_CIDRS", ""); cidrs != "" {
		uiFilterCIDRs = parseCIDRList(cidrs)
		log.Printf("[svc] UI filter: %d CIDRs active", len(uiFilterCIDRs))
	}

	// Start UDP collectors
	startFlowCollectors(bgCtx)

	// Start HTTP server
	go func() {
		log.Printf("[svc] FlowAnalyzer listening on http://%s", listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[svc] server error: %v", err)
		}
	}()

	s <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	stopped := false
	for !stopped {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				stopped = true
			default:
			}
		}
	}

	// Shutdown sequence
	bgCancel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)

	s <- svc.Status{State: svc.StopPending}
	return false, 0
}

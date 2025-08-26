package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// helper to reset the global store for tests
func resetStore() {
	store = NewStore()
}

func TestTopIPsAndProtocolEndpointsHaveData(t *testing.T) {
	resetStore()
	// Create synthetic sessions over the last 3 minutes
	now := time.Now().UTC().Truncate(time.Minute)
	sessions := []FlowSession{
		{Timestamp: now.Add(-2 * time.Minute), Router: "R1", SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "8.8.8.8", DstPort: 53, Protocol: "UDP", Bytes: 10000, Packets: 10},
		{Timestamp: now.Add(-1 * time.Minute), Router: "R1", SrcIP: "10.0.0.2", SrcPort: 23456, DstIP: "1.1.1.1", DstPort: 53, Protocol: "UDP", Bytes: 20000, Packets: 20},
		{Timestamp: now.Add(-1 * time.Minute), Router: "R1", SrcIP: "10.0.0.2", SrcPort: 23456, DstIP: "10.0.0.1", DstPort: 443, Protocol: "TCP", Bytes: 30000, Packets: 30},
		{Timestamp: now.Add(-30 * time.Second), Router: "R1", SrcIP: "10.0.0.1", SrcPort: 443, DstIP: "10.0.0.2", DstPort: 52345, Protocol: "TCP", Bytes: 40000, Packets: 40},
	}
	store.AddMany(sessions)

	// 1) /api/top_ips
	req := httptest.NewRequest("GET", "/api/top_ips?since="+url.QueryEscape(strconvI(now.Add(-10*time.Minute)))+"&until="+url.QueryEscape(strconvI(now.Add(1*time.Minute)))+"&step=60&limit=20", nil)
	rec := httptest.NewRecorder()
	topIPsHandler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("top_ips status=%d body=%s", rec.Code, rec.Body.String())
	}
	var topResp struct {
		Series []struct{
			IP string `json:"ip"`
			Points []map[string]any `json:"points"`
		} `json:"series"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &topResp); err != nil {
		t.Fatalf("unmarshal top_ips: %v", err)
	}
	if len(topResp.Series) == 0 {
		t.Fatalf("expected at least 1 series in top_ips, got 0")
	}
	if len(topResp.Series[0].Points) == 0 {
		t.Fatalf("expected points in first series, got none")
	}

	// 2) /api/metrics/throughput_by_protocol_precomputed
	req2 := httptest.NewRequest("GET", "/api/metrics/throughput_by_protocol_precomputed?since="+url.QueryEscape(strconvI(now.Add(-10*time.Minute)))+"&until="+url.QueryEscape(strconvI(now.Add(1*time.Minute)))+"&step=60", nil)
	rec2 := httptest.NewRecorder()
	throughputByProtocolPrecomputedHandler(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("proto_precomp status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "series") {
		t.Fatalf("expected series field in proto_precomp response")
	}

	// 3) /api/metrics/top by ports
	req3 := httptest.NewRequest("GET", "/api/metrics/top?by=src_port&since="+url.QueryEscape(strconvI(now.Add(-10*time.Minute)))+"&until="+url.QueryEscape(strconvI(now.Add(1*time.Minute)))+"&limit=10", nil)
	rec3 := httptest.NewRecorder()
	topHandler(rec3, req3)
	if rec3.Code != 200 {
		t.Fatalf("top src_port status=%d body=%s", rec3.Code, rec3.Body.String())
	}
	if !strings.Contains(rec3.Body.String(), "items") {
		t.Fatalf("expected items field in top src_port response")
	}
}

// helper to stringify time as unix seconds for the parseTime function to accept
func strconvI(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

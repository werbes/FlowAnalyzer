package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestIPPeersSessionsCount(t *testing.T) {
	resetStore()
	now := time.Now().UTC().Truncate(time.Minute)
	sessions := []FlowSession{
		{Timestamp: now.Add(-2 * time.Minute), Router: "R1", SrcIP: "10.0.0.1", SrcPort: 1111, DstIP: "10.0.0.2", DstPort: 2222, Protocol: "TCP", Bytes: 1000, Packets: 10},
		{Timestamp: now.Add(-1 * time.Minute), Router: "R1", SrcIP: "10.0.0.2", SrcPort: 2222, DstIP: "10.0.0.1", DstPort: 1111, Protocol: "TCP", Bytes: 2000, Packets: 20},
	}
	store.AddMany(sessions)

	since := now.Add(-10 * time.Minute)
	until := now.Add(1 * time.Minute)
	q := "/api/ip/peers?ip=10.0.0.1&since=" + url.QueryEscape(strconv.FormatInt(since.Unix(), 10)) + "&until=" + url.QueryEscape(strconv.FormatInt(until.Unix(), 10)) + "&step=60&limit=10"
	req := httptest.NewRequest("GET", q, nil)
	rec := httptest.NewRecorder()
	ipPeersHandler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("ip_peers status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Series []struct{
			Peer string `json:"peer"`
			Sessions int64 `json:"sessions"`
		} `json:"series"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal ip_peers: %v", err)
	}
	if len(resp.Series) == 0 {
		t.Fatalf("expected at least 1 peer series")
	}
	var found bool
	for _, s := range resp.Series {
		if s.Peer == "10.0.0.2" {
			found = true
			if s.Sessions <= 0 {
				t.Fatalf("expected sessions > 0 for peer 10.0.0.2, got %d", s.Sessions)
			}
		}
	}
	if !found {
		t.Fatalf("expected peer 10.0.0.2 in response")
	}
}

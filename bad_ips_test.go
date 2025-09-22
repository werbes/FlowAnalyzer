package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestBadIPsCountsUniqueDestsWithCIDRFilter(t *testing.T) {
	resetStore()
	// Restrict view to 10.0.0.0/8
	uiFilterCIDRs = parseCIDRList("10.0.0.0/8")

	now := time.Now().UTC().Truncate(time.Minute)
	var sessions []FlowSession
	// Source outside filter scanning many destinations inside filter
	src := "5.187.35.53"
	count := 1500
	for i := 0; i < count; i++ {
		// spread over 10.1.X.Y avoiding .0
		x := i / 250
		y := (i % 250) + 1
		dst := "10.1." + strconv.Itoa(x) + "." + strconv.Itoa(y)
		sessions = append(sessions, FlowSession{Timestamp: now.Add(-2 * time.Minute), Router: "R1", SrcIP: src, SrcPort: 40000 + i%1000, DstIP: dst, DstPort: 1000 + i%500, Protocol: "TCP", Bytes: 100, Packets: 1})
	}
	// Also add some destinations outside filter; they should NOT count
	for i := 0; i < 200; i++ {
		dst := "8.8." + strconv.Itoa(i%250) + "." + strconv.Itoa((i%200)+1)
		sessions = append(sessions, FlowSession{Timestamp: now.Add(-2 * time.Minute), Router: "R1", SrcIP: src, SrcPort: 45000 + i%1000, DstIP: dst, DstPort: 2000 + i%500, Protocol: "TCP", Bytes: 100, Packets: 1})
	}
	store.AddMany(sessions)

	// Query bad-ips for a window covering our data
	req := httptest.NewRequest("GET", "/api/bad-ips?since="+url.QueryEscape(strconvI(now.Add(-10*time.Minute)))+"&until="+url.QueryEscape(strconvI(now.Add(1*time.Minute)))+"&limit=10", nil)
	rec := httptest.NewRecorder()
	badIPsAPIHandler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("bad-ips status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []struct {
			IP    string `json:"ip"`
			Count int    `json:"count"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal bad-ips: %v", err)
	}
	if len(resp.Items) == 0 || resp.Items[0].IP != src {
		t.Fatalf("expected first item for %s, got %+v", src, resp.Items)
	}
	if resp.Items[0].Count != count {
		t.Fatalf("expected count=%d for %s, got %d", count, src, resp.Items[0].Count)
	}
}

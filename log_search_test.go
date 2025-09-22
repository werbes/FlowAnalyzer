package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLogsSearchHandler_Basic(t *testing.T) {
	// Setup temp TSDB root with one hour folder and one IP logs
	root := t.TempDir()
	// ensure currentTSDBRoot() will pick this root via INI-only config
	iniConfig = map[string]string{"TSDB_ROOT": root}
	now := time.Now().UTC().Truncate(time.Hour)
	y, m, d := now.Year(), int(now.Month()), now.Day()
	hh := now.Hour()
	ip := "10.20.30.40"
	octs := strings.Split(ip, ".")
	// Create directories
	dir := filepath.Join(root, strconv.Itoa(y), twoDigit(m), twoDigit(d), twoDigit(hh), octs[0], octs[1], octs[2], octs[3])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Prepare two lines: one TCP 443 dst, one UDP 53 src
	line1 := now.Format("15:04:05") + " " + now.Add(1*time.Second).Format("15:04:05") + " 1000 10 TCP 1.1.1.1:55555 > 10.20.30.40:443 router=R1\n"
	line2 := now.Format("15:04:05") + " " + now.Add(2*time.Second).Format("15:04:05") + " 2000 20 UDP 10.20.30.40:12345 > 8.8.8.8:53 router=R2\n"
	if err := os.WriteFile(filepath.Join(dir, "dst-port.log"), []byte(line1), 0o644); err != nil {
		t.Fatalf("write dst: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src-port.log"), []byte(line2), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	// Query for the IP across both sides, with page_size=1 to test pagination
	since := strconv.FormatInt(now.Unix(), 10)
	until := strconv.FormatInt(now.Add(5*time.Minute).Unix(), 10)
	u := "/api/logs/search?ip=" + url.QueryEscape(ip) + "&since=" + since + "&until=" + until + "&page_size=1"
	req := httptest.NewRequest("GET", u, nil)
	rec := httptest.NewRecorder()
	logsSearchHandler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		IP       string      `json:"ip"`
		Items    []fsLogItem `json:"items"`
		HasMore  bool        `json:"has_more"`
		NextPage int         `json:"next_page"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.IP != ip {
		t.Fatalf("expected ip %s, got %s", ip, resp.IP)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("expected 1 item (page_size=1), got %d", len(resp.Items))
	}
	if !resp.HasMore || resp.NextPage != 2 {
		t.Fatalf("expected has_more=true next_page=2, got %v %d", resp.HasMore, resp.NextPage)
	}

	// Filter by protocol UDP: should return the src item (R2)
	u2 := "/api/logs/search?ip=" + url.QueryEscape(ip) + "&since=" + since + "&until=" + until + "&protocol=udp&page_size=10"
	req2 := httptest.NewRequest("GET", u2, nil)
	rec2 := httptest.NewRecorder()
	logsSearchHandler(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("udp status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	var resp2 struct {
		Items []fsLogItem `json:"items"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("udp unmarshal: %v", err)
	}
	if len(resp2.Items) != 1 || resp2.Items[0].Protocol != "UDP" || resp2.Items[0].Router != "R2" {
		t.Fatalf("expected 1 UDP item from R2, got %+v", resp2.Items)
	}

	// Filter by port=443 should match the dst item
	u3 := "/api/logs/search?ip=" + url.QueryEscape(ip) + "&since=" + since + "&until=" + until + "&port=443&page_size=10"
	req3 := httptest.NewRequest("GET", u3, nil)
	rec3 := httptest.NewRecorder()
	logsSearchHandler(rec3, req3)
	if rec3.Code != 200 {
		t.Fatalf("port status=%d body=%s", rec3.Code, rec3.Body.String())
	}
	var resp3 struct {
		Items []fsLogItem `json:"items"`
	}
	if err := json.Unmarshal(rec3.Body.Bytes(), &resp3); err != nil {
		t.Fatalf("port unmarshal: %v", err)
	}
	if len(resp3.Items) != 1 || resp3.Items[0].DstPort != 443 {
		t.Fatalf("expected 1 item with DstPort=443, got %+v", resp3.Items)
	}
}

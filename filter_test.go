package main

import (
	"testing"
	"time"
)

func TestStoreFilter_OverlapIncluded(t *testing.T) {
	st := NewStore()
	now := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	// Session exported later (Timestamp outside window), but active earlier
	s := FlowSession{
		Timestamp: now.Add(30 * time.Minute), // export at +30m
		Start:     now.Add(2 * time.Minute),  // active 2m .. 7m
		End:       now.Add(7 * time.Minute),
		Router:    "r1",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		Protocol:  "ICMP",
		Bytes:     1000,
		Packets:   10,
	}
	st.AddMany([]FlowSession{s})

	q := Query{Router: "r1", Since: now.Add(3 * time.Minute), Until: now.Add(4 * time.Minute)}
	res := st.Filter(q)
	if len(res) != 1 {
		// With overlap-aware filter, this must be included because [2m,7m] overlaps [3m,4m]
		t.Fatalf("expected 1 result, got %d", len(res))
	}
}

func TestStoreFilter_TimestampFallback(t *testing.T) {
	st := NewStore()
	now := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	s := FlowSession{
		Timestamp: now.Add(5 * time.Minute),
		Router:    "r1",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		Protocol:  "ICMP",
		Bytes:     500,
		Packets:   5,
	}
	st.AddMany([]FlowSession{s})

	qInside := Query{Router: "r1", Since: now.Add(4 * time.Minute), Until: now.Add(6 * time.Minute)}
	resInside := st.Filter(qInside)
	if len(resInside) != 1 {
		t.Fatalf("expected 1 result inside window, got %d", len(resInside))
	}
	qOutside := Query{Router: "r1", Since: now.Add(6 * time.Minute), Until: now.Add(7 * time.Minute)}
	resOutside := st.Filter(qOutside)
	if len(resOutside) != 0 {
		t.Fatalf("expected 0 results outside window, got %d", len(resOutside))
	}
}

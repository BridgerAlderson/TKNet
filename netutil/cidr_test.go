package netutil

import (
	"encoding/json"
	"net"
	"os"
	"testing"
)

func TestParseTargetsSharedScopeFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/scopes.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name, Input, First, Last string
		Count                    uint64
		Valid                    bool
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, tt := range fixtures {
		t.Run(tt.Name, func(t *testing.T) {
			got, err := ParseTargets(tt.Input)
			if !tt.Valid {
				if err == nil || got != nil {
					t.Fatalf("invalid scope was partially accepted: %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Count() != tt.Count {
				t.Fatalf("count=%d want=%d", got.Count(), tt.Count)
			}
			var count uint64
			var first, last net.IP
			for ip := range got.IPs() {
				if first == nil {
					first = ip
				}
				if last != nil && ipv4Value(ip) <= ipv4Value(last) {
					t.Fatal("duplicate or unsorted IP")
				}
				last = ip
				count++
				// /8 and /0 must parse and begin yielding immediately, without
				// allocating or walking millions of addresses before cancellation.
				if tt.Count > 200000 && count == 8 {
					break
				}
			}
			if tt.Count > 0 && first.String() != tt.First {
				t.Fatalf("first=%v want=%s", first, tt.First)
			}
			if tt.Count <= 200000 && (count != tt.Count || (count > 0 && last.String() != tt.Last)) {
				t.Fatalf("enumeration count=%d last=%v", count, last)
			}
		})
	}
}

func ipv4Value(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func TestTargetsIteratorsAreIndependent(t *testing.T) {
	targets, err := ParseTargets("255.255.255.253-255.255.255.255")
	if err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 3; run++ {
		var values []net.IP
		for ip := range targets.IPs() {
			values = append(values, ip)
		}
		if len(values) != 3 || values[0].String() != "255.255.255.253" || values[2].String() != "255.255.255.255" {
			t.Fatal("iterator reused mutable IP storage or wrapped around the IPv4 endpoint")
		}
	}
}

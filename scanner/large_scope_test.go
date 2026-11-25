package scanner

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func largeScopeFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../netutil/testdata/scopes.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct{ Name, Input string }
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		if f.Name == "mixed large CIDRs" {
			return f.Input
		}
	}
	t.Fatal("missing large-scope fixture")
	return ""
}

func assertFinalProgress(t *testing.T, e *Engine) {
	t.Helper()
	last := 0.0
	for p := range e.ProgressChan {
		if p < last || p > 1 {
			t.Fatalf("invalid progress %v after %v", p, last)
		}
		last = p
	}
	if last != 1 {
		t.Fatalf("incomplete progress: %v", last)
	}
	for message := range e.LogChan {
		if strings.HasPrefix(message, "ERROR:") {
			t.Fatal(message)
		}
	}
}

// No sockets, credentials or real SMB servers are used. The production target
// parser, dispatch, TCP-recovery scheduling and result channels process the full
// 134884-address workload, with one final result per unique address.
func TestLargeScopeSMBDeliveryAndRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e := NewEngine()
	var initial, retried atomic.Uint64
	scope := largeScopeFixture(t)
	go e.runSMBScan(ctx, ScanConfig{Targets: scope, Threads: 50, Timeout: 10},
		func(_ context.Context, ip string, cfg ScanConfig) ScanResult {
			if cfg.Threads != 50 || cfg.Timeout != 10 {
				t.Error("settings changed")
			}
			if !cfg.connectionRecovery {
				initial.Add(1)
				if net.ParseIP(ip).To4()[3] == 17 {
					return ScanResult{IP: ip, EnumerationStatus: "Not attempted", retryConnection: true,
						ConnectionAttempts: 3, ConnectionErrors: []string{"timeout", "timeout", "timeout"}}
				}
			} else {
				retried.Add(1)
				if net.ParseIP(ip).To4()[3] != 17 || initial.Load() != 134884 {
					t.Error("unexpected/early recovery")
				}
			}
			return ScanResult{IP: ip, Port445Open: true, ConnectionAttempts: 1, EnumerationStatus: "Complete", Shares: []ShareInfo{{Name: "Fixture"}}}
		})
	seen := make(map[string]bool)
	var recovered uint64
	for r := range e.ScanResults {
		if seen[r.IP] {
			t.Fatalf("duplicate result: %s", r.IP)
		}
		seen[r.IP] = true
		if !r.Port445Open || len(r.Shares) != 1 {
			t.Fatalf("lost result: %+v", r)
		}
		if r.ConnectionRecoveryAttempted {
			recovered++
			if r.ConnectionAttempts != 4 || len(r.ConnectionErrors) != 3 {
				t.Fatal("lost recovery history")
			}
		} else if r.ConnectionAttempts != 1 {
			t.Fatal("unexpected repeat")
		}
	}
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	if len(seen) != 134884 || initial.Load() != 134884 || recovered == 0 || recovered != retried.Load() {
		t.Fatalf("results=%d initial=%d recovered=%d retried=%d", len(seen), initial.Load(), recovered, retried.Load())
	}
	assertFinalProgress(t, e)
	t.Logf("%d unique results, %d TCP-only recovery targets, complete progress", len(seen), recovered)
}

func TestLargeScopeDiscoveryDelivery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e := NewEngine()
	p := silentProbes()
	var calls atomic.Uint64
	p.ping = func(_ context.Context, ip net.IP, timeout uint32) (bool, uint32, error) {
		calls.Add(1)
		if timeout != 10000 {
			t.Error("timeout changed")
		}
		return ip.To4()[3] != 13, 1, nil
	}
	cfg := AliveConfig{Targets: largeScopeFixture(t), Threads: 50, Timeout: 10, Attempts: 1, EnableICMP: true}
	go e.runAliveDiscoveryWithProbes(ctx, cfg, p)
	seen := make(map[string]bool)
	for r := range e.AliveResults {
		if seen[r.IP] {
			t.Fatalf("duplicate result: %s", r.IP)
		}
		seen[r.IP] = true
		wantAlive := net.ParseIP(r.IP).To4()[3] != 13
		if r.IsAlive != wantAlive || r.Attempts != 1 || r.Error != "" {
			t.Fatalf("changed probe evidence: %+v", r)
		}
	}
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	if len(seen) != 134884 || calls.Load() != 134884 {
		t.Fatalf("results=%d probes=%d", len(seen), calls.Load())
	}
	assertFinalProgress(t, e)
}

func TestFullIPv4ScopeStartsAndCancelsWithoutExpansion(t *testing.T) {
	for _, mode := range []string{"smb", "discovery"} {
		for _, before := range []bool{false, true} {
			t.Run(mode+map[bool]string{true: "/cancel-before", false: "/cancel-active"}[before], func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if before {
					cancel()
				}
				e := NewEngine()
				done := make(chan struct{})
				var calls atomic.Int32
				go func() {
					defer close(done)
					if mode == "smb" {
						e.runSMBScan(ctx, ScanConfig{Targets: "0.0.0.0/0", Threads: 4}, func(_ context.Context, ip string, _ ScanConfig) ScanResult {
							calls.Add(1)
							cancel()
							return ScanResult{IP: ip}
						})
					} else {
						p := silentProbes()
						p.ping = func(context.Context, net.IP, uint32) (bool, uint32, error) {
							calls.Add(1)
							cancel()
							return false, 0, nil
						}
						e.runAliveDiscoveryWithProbes(ctx, AliveConfig{Targets: "0.0.0.0/0", Threads: 4, EnableICMP: true}, p)
					}
				}()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("/0 was expanded before cancellation")
				}
				if (before && calls.Load() != 0) || (!before && calls.Load() == 0) || calls.Load() > 4 {
					t.Fatalf("unexpected calls: %d", calls.Load())
				}
				for message := range e.LogChan {
					if strings.Contains(message, "completed") || strings.Contains(message, "exceeds") {
						t.Fatal(message)
					}
				}
			})
		}
	}
}

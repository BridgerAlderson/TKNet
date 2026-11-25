package scanner

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the real scheduler with blocked hosts, independent of network timing.
// Each host returns a known list so scheduling and result delivery are checked
// separately from the SMB enumeration/transport fixtures.
func TestSMBSettingsControlConcurrencyWithoutLosingResults(t *testing.T) {
	const hosts = 17
	shares := []ShareInfo{{Name: "Public", CanRead: true}, {Name: "Hidden$"}, {Name: "資料", CanWrite: true}}
	for _, threads := range []int{1, 4, 50, 256} {
		for _, timeout := range []int{1, 10, 30, 60} {
			t.Run(fmt.Sprintf("threads=%d/timeout=%d", threads, timeout), func(t *testing.T) {
				engine := NewEngine()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cfg := ScanConfig{Targets: "192.0.2.1-17", Threads: threads, Timeout: timeout}
				started := make(chan ScanConfig, hosts)
				release := make(chan struct{})
				finished := make(chan struct{})
				var active, peak atomic.Int32
				go func() {
					defer close(finished)
					engine.runSMBScan(ctx, cfg, func(ctx context.Context, ip string, received ScanConfig) ScanResult {
						current := active.Add(1)
						defer active.Add(-1)
						for previous := peak.Load(); current > previous; previous = peak.Load() {
							if peak.CompareAndSwap(previous, current) {
								break
							}
						}
						started <- received
						select {
						case <-release:
						case <-ctx.Done():
						}
						return ScanResult{IP: ip, Shares: shares, EnumerationStatus: "Complete", Status: "Done"}
					})
				}()
				defer func() {
					cancel()
					select {
					case <-finished:
					case <-time.After(time.Second):
						t.Error("scheduler did not finish after cancellation")
					}
				}()

				wantParallel := min(threads, hosts)
				for i := 0; i < wantParallel; i++ {
					select {
					case received := <-started:
						if received != cfg {
							t.Fatalf("settings changed before host check: got %+v, want %+v", received, cfg)
						}
					case <-ctx.Done():
						t.Fatalf("only %d of %d configured workers started", i, wantParallel)
					}
				}
				close(release)
				seen := make(map[string]bool, hosts)
			results:
				for {
					select {
					case result, ok := <-engine.ScanResults:
						if !ok {
							break results
						}
						if seen[result.IP] || !reflect.DeepEqual(result.Shares, shares) || result.EnumerationStatus != "Complete" {
							t.Fatalf("duplicated or damaged result: %+v", result)
						}
						seen[result.IP] = true
					case <-ctx.Done():
						t.Fatal("result delivery did not complete")
					}
				}
				if int(peak.Load()) != wantParallel || active.Load() != 0 {
					t.Fatalf("peak=%d, want=%d, still active=%d", peak.Load(), wantParallel, active.Load())
				}
				for i := 1; i <= hosts; i++ {
					if !seen[fmt.Sprintf("192.0.2.%d", i)] {
						t.Fatalf("host %d missing from completed results", i)
					}
				}
				for len(started) > 0 {
					if received := <-started; received != cfg {
						t.Fatalf("later host received different settings: %+v", received)
					}
				}
			})
		}
	}
}

func TestSMBFinalConnectionSweepIsBoundedAndPublishesOnce(t *testing.T) {
	for _, threads := range []int{1, 4, 50} {
		t.Run(fmt.Sprintf("threads=%d", threads), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			e := NewEngine()
			var initial, active, peak atomic.Int32
			started := make(chan struct{}, 17)
			release := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				e.runSMBScan(ctx, ScanConfig{Targets: "192.0.2.1-17", Threads: threads, Timeout: 10}, func(ctx context.Context, ip string, cfg ScanConfig) ScanResult {
					if !cfg.connectionRecovery {
						initial.Add(1)
						if ip == "192.0.2.1" {
							// An actual connection with an auth failure must NOT be retried.
							return ScanResult{IP: ip, Port445Open: true, ConnectionAttempts: 1, EnumerationStatus: "Not attempted", Error: "Configured account rejected"}
						}
						return ScanResult{IP: ip, ConnectionAttempts: 3, ConnectionErrors: []string{"timeout", "timeout", "timeout"}, EnumerationStatus: "Not attempted", retryConnection: true}
					}
					if initial.Load() != 17 || ip == "192.0.2.1" || cfg.Timeout != 10 || cfg.Threads != threads {
						t.Error("recovery started early, changed settings, or retried an authenticated host")
					}
					n := active.Add(1)
					defer active.Add(-1)
					for previous := peak.Load(); n > previous; previous = peak.Load() {
						if peak.CompareAndSwap(previous, n) {
							break
						}
					}
					started <- struct{}{}
					select {
					case <-release:
					case <-ctx.Done():
					}
					return ScanResult{IP: ip, Port445Open: true, ConnectionAttempts: 1, EnumerationStatus: "Complete", Shares: []ShareInfo{{Name: "Public"}}}
				})
			}()
			for i := 0; i < min(threads, 8); i++ {
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("recovery workers did not start")
				}
			}
			close(release)
			seen := make(map[string]bool)
			for result := range e.ScanResults {
				if seen[result.IP] {
					t.Fatal("duplicate final result")
				}
				seen[result.IP] = true
				if result.IP == "192.0.2.1" {
					if result.ConnectionRecoveryAttempted || result.ConnectionAttempts != 1 {
						t.Fatal("auth failure was retried")
					}
				} else if !result.ConnectionRecoveryAttempted || result.ConnectionAttempts != 4 || len(result.ConnectionErrors) != 3 || len(result.Shares) != 1 {
					t.Fatalf("lost final sweep history or result: %+v", result)
				}
			}
			<-done
			if len(seen) != 17 || int(peak.Load()) != min(threads, 8) {
				t.Fatalf("hosts=%d concurrency=%d", len(seen), peak.Load())
			}
			progress := float64(0)
			for value := range e.ProgressChan {
				if value < progress {
					t.Fatal("progress went backwards")
				}
				progress = value
			}
			if progress != 1 {
				t.Fatal("final sweep did not reach complete progress")
			}
		})
	}
}

func TestSMBFinalConnectionSweepCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := NewEngine()
	started := make(chan struct{}, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.runSMBScan(ctx, ScanConfig{Targets: "192.0.2.1-17", Threads: 50, Timeout: 10}, func(ctx context.Context, ip string, cfg ScanConfig) ScanResult {
			if cfg.connectionRecovery {
				started <- struct{}{}
				<-ctx.Done()
			}
			return ScanResult{IP: ip, EnumerationStatus: "Not attempted", retryConnection: true}
		})
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("recovery did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled recovery did not stop")
	}
}

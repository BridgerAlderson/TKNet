package scanner

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestRetryRecoversFirstLostReply(t *testing.T) {
	for _, method := range []string{"ICMP", "TCP", "NetBIOS"} {
		t.Run(method, func(t *testing.T) {
			cfg := testConfig()
			cfg.Attempts = 2
			p := silentProbes()
			var calls atomic.Int32
			switch method {
			case "ICMP":
				p.ping = func(context.Context, net.IP, uint32) (bool, uint32, error) { return calls.Add(1) > 1, 1, nil }
			case "TCP":
				cfg.TCPPorts = []int{445}
				p.tcp = func(context.Context, string, time.Duration) error {
					if calls.Add(1) == 1 {
						return context.DeadlineExceeded
					}
					return nil
				}
			case "NetBIOS":
				p.nbns = func(context.Context, net.IP, time.Duration) (string, error) {
					if calls.Add(1) == 1 {
						return "", context.DeadlineExceeded
					}
					return "HOST", nil
				}
			}
			got := checkAlive(context.Background(), net.ParseIP("192.0.2.1"), cfg, p)
			if !got.IsAlive || got.Attempts != 2 || calls.Load() != 2 {
				t.Fatalf("retry failed: %+v calls=%d", got, calls.Load())
			}
			if got.CheckedAt == "" || len(got.ProbeOutcomes) == 0 {
				t.Fatal("missing evidence")
			}
			found := false
			for _, outcome := range got.ProbeOutcomes {
				if outcome.Attempt == 2 && outcome.Outcome == "confirmed" {
					found = true
				}
			}
			if !found {
				t.Fatal("second-attempt evidence missing")
			}
		})
	}
}

func TestRetryDoesNotPromoteUnconfirmedEvidence(t *testing.T) {
	cfg := testConfig()
	cfg.Attempts = 2
	p := silentProbes()
	p.arp = func(context.Context, net.IP, time.Duration) (bool, string, error) {
		return true, "02:00:00:00:00:01", nil
	}
	p.tcp = func(context.Context, string, time.Duration) error { return syscall.ECONNREFUSED }
	got := checkAlive(context.Background(), net.ParseIP("192.0.2.1"), cfg, p)
	if got.IsAlive || got.Attempts != 2 || !got.ARPObserved || len(got.TCPRefusedPorts) != 2 || len(got.TCPOpenPorts) != 0 {
		t.Fatalf("uncertain evidence became alive/open: %+v", got)
	}
}

func TestNoRetryAfterConfirmationOrTotalToolFailure(t *testing.T) {
	cfg := AliveConfig{EnableICMP: true, Attempts: 3, Timeout: 1}
	p := silentProbes()
	var calls atomic.Int32
	p.ping = func(context.Context, net.IP, uint32) (bool, uint32, error) { calls.Add(1); return true, 1, nil }
	got := checkAlive(context.Background(), net.ParseIP("192.0.2.1"), cfg, p)
	if got.Attempts != 1 || calls.Load() != 1 {
		t.Fatal("confirmed host was retried")
	}
	calls.Store(0)
	p.ping = func(context.Context, net.IP, uint32) (bool, uint32, error) {
		calls.Add(1)
		return false, 0, errors.New("tool unavailable")
	}
	got = checkAlive(context.Background(), net.ParseIP("192.0.2.1"), cfg, p)
	if got.IsAlive || got.Status != "Incomplete (probe errors)" || got.Attempts != 1 || calls.Load() != 1 {
		t.Fatalf("local failure lost or retried: %+v", got)
	}
}

func TestCancellationDuringRetryBackoff(t *testing.T) {
	cfg := AliveConfig{EnableICMP: true, Attempts: 3, Timeout: 1}
	p := silentProbes()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var calls atomic.Int32
	p.ping = func(context.Context, net.IP, uint32) (bool, uint32, error) { calls.Add(1); return false, 0, nil }
	got := checkAlive(ctx, net.ParseIP("192.0.2.1"), cfg, p)
	if got.IsAlive || got.Status != "Cancelled" || calls.Load() != 1 {
		t.Fatalf("cancelled retry ran: %+v calls=%d", got, calls.Load())
	}
}

func TestSharedProbeLimitAcrossHosts(t *testing.T) {
	cfg := AliveConfig{EnableTCP: true, TCPPorts: []int{80, 443, 445}, Attempts: 1, Timeout: 1}
	p := silentProbes()
	p.limit = make(chan struct{}, 2)
	var current, peak, completed atomic.Int32
	p.tcp = func(context.Context, string, time.Duration) error {
		now := current.Add(1)
		for old := peak.Load(); now > old; old = peak.Load() {
			if peak.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		current.Add(-1)
		completed.Add(1)
		return nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); checkAlive(context.Background(), net.ParseIP("192.0.2.1"), cfg, p) }()
	}
	wg.Wait()
	if peak.Load() > 2 || completed.Load() != 36 || current.Load() != 0 {
		t.Fatalf("limit leaked: peak=%d completed=%d active=%d", peak.Load(), completed.Load(), current.Load())
	}
}

func TestCancelledProbeWaitDoesNotAcquireSlot(t *testing.T) {
	p := silentProbes()
	p.limit = make(chan struct{}, 1)
	p.limit <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p.acquire(ctx) {
		t.Fatal("cancelled waiter acquired a probe slot")
	}
	if len(p.limit) != 1 {
		t.Fatal("existing permit lost")
	}
}

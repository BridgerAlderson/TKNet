package scanner

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"tknet/netutil"
)

func testConfig() AliveConfig {
	return AliveConfig{Threads: 2, Timeout: 1, Attempts: 1, EnableARP: true, EnableICMP: true, EnableTCP: true, EnableNetBIOS: true, EnableDNS: true, TCPPorts: []int{445, 80, 445}}
}
func silentProbes() aliveProbes {
	return aliveProbes{
		arp:  func(context.Context, net.IP, time.Duration) (bool, string, error) { return false, "", nil },
		ping: func(context.Context, net.IP, uint32) (bool, uint32, error) { return false, 0, nil },
		nbns: func(context.Context, net.IP, time.Duration) (string, error) { return "", netutil.ErrNoResponse },
		tcp:  func(context.Context, string, time.Duration) error { return context.DeadlineExceeded },
		dns:  func(context.Context, string) ([]string, error) { return []string{"stale.example."}, nil },
	}
}
func TestDiscoveryEvidence(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(*aliveProbes)
		alive          bool
		status, method string
	}{
		{"no response", func(*aliveProbes) {}, false, "No response", ""},
		{"ARP and stale PTR are not alive", func(p *aliveProbes) {
			p.arp = func(context.Context, net.IP, time.Duration) (bool, string, error) {
				return true, "02:00:00:00:00:01", nil
			}
		}, false, "Unconfirmed (ARP only)", ""},
		{"invalid MAC discarded", func(p *aliveProbes) {
			p.arp = func(context.Context, net.IP, time.Duration) (bool, string, error) {
				return true, "ff:ff:ff:ff:ff:ff", nil
			}
		}, false, "Incomplete (probe errors)", ""},
		{"verified echo", func(p *aliveProbes) {
			p.ping = func(context.Context, net.IP, uint32) (bool, uint32, error) { return true, 2, nil }
		}, true, "Confirmed", "ICMP"},
		{"successful TCP", func(p *aliveProbes) { p.tcp = func(context.Context, string, time.Duration) error { return nil } }, true, "Confirmed", "TCP:80, TCP:445"},
		{"valid nameless NBSTAT", func(p *aliveProbes) {
			p.nbns = func(context.Context, net.IP, time.Duration) (string, error) { return "", nil }
		}, true, "Confirmed", "NetBIOS"},
		{"bad NBSTAT with a name", func(p *aliveProbes) {
			p.nbns = func(context.Context, net.IP, time.Duration) (string, error) {
				return "WRONG", errors.New("invalid response")
			}
		}, false, "Incomplete (probe errors)", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := silentProbes()
			tt.setup(&p)
			got := checkAlive(context.Background(), net.ParseIP("192.0.2.1"), testConfig(), p)
			if got.IsAlive != tt.alive || got.Status != tt.status || got.DetectionMethod != tt.method {
				t.Fatalf("unexpected result: %+v", got)
			}
			if strings.Contains(got.DetectionMethod, "DNS") || strings.Contains(got.DetectionMethod, "ARP") {
				t.Fatal("metadata reported as proof")
			}
		})
	}
}
func TestDiscoveryFallbackMetadataAndWarnings(t *testing.T) {
	p := silentProbes()
	var tcpCalls atomic.Int32
	p.tcp = func(context.Context, string, time.Duration) error { tcpCalls.Add(1); return nil }
	p.ping = func(context.Context, net.IP, uint32) (bool, uint32, error) { return true, 1, nil }
	p.nbns = func(context.Context, net.IP, time.Duration) (string, error) { return "WORKSTATION", nil }
	got := checkAlive(context.Background(), net.ParseIP("192.0.2.1"), testConfig(), p)
	if tcpCalls.Load() != 0 || got.Hostname != "stale.example" || got.DetectionMethod != "ICMP, NetBIOS" {
		t.Fatalf("%+v; TCP calls=%d", got, tcpCalls.Load())
	}
	p.ping = func(context.Context, net.IP, uint32) (bool, uint32, error) {
		return false, 0, errors.New("ping unavailable")
	}
	p.tcp = func(context.Context, string, time.Duration) error { return syscall.EMFILE }
	got = checkAlive(context.Background(), net.ParseIP("192.0.2.1"), testConfig(), p)
	if !got.IsAlive || len(got.Warnings) != 3 {
		t.Fatalf("probe failure lost: %+v", got)
	}
}
func TestDiscoveryCancellation(t *testing.T) {
	p := silentProbes()
	ctx, cancel := context.WithCancel(context.Background())
	p.ping = func(ctx context.Context, _ net.IP, _ uint32) (bool, uint32, error) { cancel(); return true, 1, nil }
	got := checkAlive(ctx, net.ParseIP("192.0.2.1"), testConfig(), p)
	if got.IsAlive || got.Status != "Cancelled" {
		t.Fatalf("cancelled scan confirmed a host: %+v", got)
	}
}
func TestAliveConfigValidation(t *testing.T) {
	got, err := NormalizeAliveConfig(AliveConfig{EnableICMP: true})
	if err != nil || got.Threads != 50 || got.Timeout != 3 || got.Attempts != 2 {
		t.Fatalf("defaults: %+v %v", got, err)
	}
	got, err = NormalizeAliveConfig(testConfig())
	if err != nil || !reflect.DeepEqual(got.TCPPorts, []int{80, 445}) {
		t.Fatalf("ports: %+v %v", got, err)
	}
	for _, cfg := range []AliveConfig{
		{EnableDNS: true}, {EnableARP: true}, {EnableTCP: true},
		{EnableICMP: true, Attempts: -1}, {EnableICMP: true, Attempts: 4},
		{EnableICMP: true, Threads: -1}, {EnableICMP: true, Threads: 257},
		{EnableICMP: true, Timeout: -1}, {EnableICMP: true, Timeout: 61},
		{EnableTCP: true, TCPPorts: []int{0}}, {EnableTCP: true, TCPPorts: []int{65536}},
	} {
		if _, err := NormalizeAliveConfig(cfg); err == nil {
			t.Fatalf("accepted invalid config: %+v", cfg)
		}
	}
}

func TestEngineRejectsInvalidConfigAndClosesStreams(t *testing.T) {
	e := NewEngine()
	e.StartAliveDiscovery(AliveConfig{Targets: "192.0.2.1", Threads: -1, EnableICMP: true})
	timer := time.After(time.Second)
	var logs []string
	logCh, progressCh, resultCh := e.LogChan, e.ProgressChan, e.AliveResults
	for logCh != nil || progressCh != nil || resultCh != nil {
		select {
		case msg, ok := <-logCh:
			if !ok {
				logCh = nil
			} else {
				logs = append(logs, msg)
			}
		case _, ok := <-progressCh:
			if !ok {
				progressCh = nil
			}
		case _, ok := <-resultCh:
			if !ok {
				resultCh = nil
			} else {
				t.Fatal("invalid config emitted a result")
			}
		case <-timer:
			t.Fatal("engine did not close all streams")
		}
	}
	if len(logs) != 1 || !strings.HasPrefix(logs[0], "ERROR:") {
		t.Fatalf("%v", logs)
	}
}

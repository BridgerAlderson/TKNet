package scanner

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSMBConfigRejectsInvalidInputBeforeIO(t *testing.T) {
	for _, cfg := range []ScanConfig{
		{Threads: -1}, {Threads: 257}, {Timeout: -1}, {Timeout: 61},
		{UseHash: true}, {UseHash: true, Username: "test", Password: "invalid"},
	} {
		if _, err := NormalizeScanConfig(cfg); err == nil {
			t.Fatalf("invalid settings accepted: %+v", cfg)
		}
		result := CheckSMB(context.Background(), "not-an-address", cfg)
		if result.Port445Open || result.Error == "" {
			t.Fatal("invalid settings were not rejected")
		}
	}
	cfg, err := NormalizeScanConfig(ScanConfig{})
	if err != nil || cfg.Threads != 50 || cfg.Timeout != 3 {
		t.Fatal("defaults changed")
	}
	if _, err := NormalizeScanConfig(ScanConfig{PortScanOnly: true, UseHash: true}); err != nil {
		t.Fatal("unused credentials rejected in port-only mode")
	}
}

func TestSMBConnectionCancellationAndActiveTimeout(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		for _, cancellation := range []bool{false, true} {
			t.Run(operation+"/"+map[bool]string{false: "timeout", true: "cancel"}[cancellation], func(t *testing.T) {
				local, peer := net.Pipe()
				defer peer.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				timeout := 30 * time.Millisecond
				if cancellation {
					timeout = time.Hour
				}
				conn := guardSMBConnection(ctx, local, timeout)
				defer conn.Close()
				finished := make(chan error, 1)
				go func() {
					_, err := smbOperation(conn, func() (int, error) {
						if operation == "read" {
							return conn.Read(make([]byte, 1))
						}
						return conn.Write([]byte{1})
					})
					finished <- err
				}()
				if cancellation {
					cancel()
				}
				select {
				case err := <-finished:
					if err == nil {
						t.Fatal("stalled I/O succeeded")
					}
					if !cancellation {
						var networkError net.Error
						if !errors.As(err, &networkError) || !networkError.Timeout() {
							t.Fatalf("not a timeout: %v", err)
						}
					}
				case <-time.After(time.Second):
					t.Fatal("stalled I/O did not stop")
				}
			})
		}
	}
}

func TestSMBProgressDoesNotBlockResults(t *testing.T) {
	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go engine.runSMBScan(ctx, ScanConfig{Targets: "192.0.2.1-120", Threads: 4}, func(ctx context.Context, ip string, cfg ScanConfig) ScanResult {
		return ScanResult{IP: ip, Status: "Done"}
	})
	count := 0
loop:
	for {
		select {
		case _, ok := <-engine.ScanResults:
			if !ok {
				break loop
			}
			count++
		case <-ctx.Done():
			t.Fatal("workers stalled behind progress")
		}
	}
	if count != 120 {
		t.Fatalf("results lost: %d", count)
	}
	previous := 0.0
	for value := range engine.ProgressChan {
		if value < previous {
			t.Fatal("progress went backwards")
		}
		previous = value
	}
	if previous != 1 {
		t.Fatalf("final progress=%v", previous)
	}
}

func TestSMBCancelWithUndrainedResults(t *testing.T) {
	engine := NewEngine()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, finished := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	go func() {
		engine.runSMBScan(ctx, ScanConfig{Targets: "192.0.2.1-200", Threads: 4}, func(ctx context.Context, ip string, cfg ScanConfig) ScanResult {
			if calls.Add(1) == 104 {
				close(ready)
			}
			return ScanResult{IP: ip}
		})
		close(finished)
	}()
	// The result buffer holds 100 records; at most four additional workers can block.
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("workers never started")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancel blocked on undrained channels")
	}
	for message := range engine.LogChan {
		if strings.Contains(message, "completed") {
			t.Fatal("cancelled scan reported success")
		}
	}
}

func TestEngineCannotRestartClosedChannels(t *testing.T) {
	engine := NewEngine()
	engine.StartSMBScan(ScanConfig{Threads: -1})
	for range engine.ScanResults {
	}
	engine.StartSMBScan(ScanConfig{Threads: -1})
	engine.StartAliveDiscovery(AliveConfig{Threads: -1})
	engine.Stop()
}

func TestWriteCheckPreservesExistingFilesAndReportsCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(path, []byte("must survive"), 0600); err != nil {
		t.Fatal(err)
	}
	open := func(path string, flags int, mode os.FileMode) (io.Closer, error) {
		return os.OpenFile(path, flags, mode)
	}
	writable, warnings := checkShareWrite(path, open, os.Remove)
	if writable || len(warnings) != 0 {
		t.Fatal("existing file treated as new test file")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "must survive" {
		t.Fatal("existing file was changed")
	}
	fresh := filepath.Join(t.TempDir(), "test.tmp")
	writable, warnings = checkShareWrite(fresh, open, os.Remove)
	if !writable || len(warnings) != 0 {
		t.Fatalf("write/cleanup failed: %v", warnings)
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatal("test file was not removed")
	}
	writable, warnings = checkShareWrite(fresh, open, func(string) error { return os.ErrPermission })
	if !writable || len(warnings) != 1 || !strings.Contains(warnings[0], fresh) {
		t.Fatal("cleanup failure was hidden")
	}
}

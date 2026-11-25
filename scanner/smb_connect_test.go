package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
)

func TestSMBInitialConnectionRecovery(t *testing.T) {
	for _, reason := range []error{context.DeadlineExceeded, syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ECONNRESET, syscall.ENETUNREACH} {
		t.Run(reason.Error(), func(t *testing.T) {
			b := newSMBFixture()
			calls, waits := 0, 0
			dial := func(ctx context.Context, target string, timeout time.Duration) (net.Conn, error) {
				calls++
				if target != "192.0.2.10:445" || timeout != 10*time.Second {
					t.Fatal("TCP settings changed")
				}
				if calls < 3 {
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: reason}
				}
				return &smbFixtureConn{fixture: b}, nil
			}
			wait := func(ctx context.Context, delay time.Duration) error {
				waits++
				if delay < 200*time.Millisecond || delay >= 600*time.Millisecond {
					t.Fatalf("unbounded retry delay: %v", delay)
				}
				return nil
			}
			conn, failures, err := connectSMB(context.Background(), "192.0.2.10:445", 10*time.Second, smbConnectAttempts, dial, wait)
			if err != nil || conn == nil || calls != 3 || waits != 2 || len(failures) != 2 || len(b.auth) != 0 {
				t.Fatalf("recovery failed: calls=%d waits=%d failures=%v error=%v", calls, waits, failures, err)
			}
			conn.Close()
		})
	}
}

func TestSMBInitialConnectionRetriesAreBoundedAndCancellable(t *testing.T) {
	for _, mode := range []string{"persistent-timeout", "permission", "cancel-before", "cancel-wait"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel-before" {
				cancel()
			}
			calls := 0
			dial := func(context.Context, string, time.Duration) (net.Conn, error) {
				calls++
				if mode == "permission" {
					return nil, syscall.EACCES
				}
				return nil, &net.OpError{Op: "dial", Err: context.DeadlineExceeded}
			}
			wait := func(ctx context.Context, _ time.Duration) error {
				if mode == "cancel-wait" {
					cancel()
					return waitSMBConnect(ctx, time.Hour)
				}
				return nil
			}
			conn, failures, err := connectSMB(ctx, "192.0.2.10:445", time.Second, smbConnectAttempts, dial, wait)
			want := map[string]int{"persistent-timeout": 3, "permission": 1, "cancel-before": 0, "cancel-wait": 1}[mode]
			if conn != nil || err == nil || calls != want || len(failures) != want {
				t.Fatalf("wrong retry boundary: calls=%d failures=%v err=%v", calls, failures, err)
			}
		})
	}
}

// Match the reported workload size/settings with independently changing initial
// TCP failures. Known-down hosts stay down; recovered hosts authenticate once.
func TestSMB995HostsRemainConsistentAcrossTransientConnectFailures(t *testing.T) {
	const hosts = 995
	var previous map[string]ScanResult
	for run := 0; run < 3; run++ {
		engine := NewEngine()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		var fixtures sync.Map
		done := make(chan struct{})
		go func() {
			defer close(done)
			engine.runSMBScan(ctx, ScanConfig{Targets: "192.0.0.1-192.0.3.227", Threads: 50, Timeout: 10},
				func(ctx context.Context, ip string, cfg ScanConfig) ScanResult {
					parsed := net.ParseIP(ip).To4()
					index := int(parsed[2])*256 + int(parsed[3])
					b := &unstableConnectFixture{smbFixture: newSMBFixture()}
					b.names = []string{"Public", "Hidden$", "資料"}
					if index <= 84 {
						b.failures = 4
					} else if (index+run)%13 == 0 {
						b.failures = 3 // Only the final, lower-load pass can recover this host.
					} else if (index+run)%7 == 0 {
						b.failures = 1 + (index+run)%2
					}
					// Include permanent authorization failures: no retries or
					// disappearance of names, even when permissions are denied.
					b.deniedAt = "mount"
					existing, _ := fixtures.LoadOrStore(ip, b)
					b = existing.(*unstableConnectFixture)
					cfg.Username, cfg.Password, cfg.Domain = "fixture-user", "synthetic", "EXAMPLE"
					return checkSMB(ctx, ip, cfg, b)
				})
		}()
		results := make(map[string]ScanResult, hosts)
		for result := range engine.ScanResults {
			if _, exists := results[result.IP]; exists {
				t.Errorf("duplicate result for %s", result.IP)
			}
			results[result.IP] = result
		}
		<-done
		cancel()
		if len(results) != hosts {
			t.Fatalf("run %d lost hosts: %d", run, len(results))
		}
		reachable, shares, recovered, lateRecovered := 0, 0, 0, 0
		for ip, result := range results {
			value, _ := fixtures.Load(ip)
			b := value.(*unstableConnectFixture)
			if result.Port445Open {
				reachable++
				if result.ConnectionRecoveryAttempted {
					lateRecovered++
				}
				shares += len(result.Shares)
				if result.ConnectionAttempts > 1 {
					recovered++
				}
				if len(b.auth) != 1 || result.Error != "" || result.EnumerationStatus != "Complete" || result.ConnectionAttempts != b.calls {
					t.Fatalf("unexpected authentication/recovery for %s: %+v", ip, result)
				}
			} else if len(b.auth) != 0 || result.ConnectionAttempts != 4 || !result.ConnectionRecoveryAttempted || result.Error == "" {
				t.Fatalf("down host authenticated or became reachable: %+v", result)
			}
			if previous != nil && (previous[ip].Port445Open != result.Port445Open || !reflect.DeepEqual(previous[ip].Shares, result.Shares)) {
				t.Fatalf("same server's shares changed after transient TCP failures: %s", ip)
			}
		}
		if reachable != 911 || shares != 2733 || recovered == 0 || lateRecovered == 0 {
			t.Fatalf("run %d: reachable=%d shares=%d recovered=%d", run, reachable, shares, recovered)
		}
		t.Logf("run %d: %d reachable, %d shares, %d recovered before authentication (%d in final sweep)", run+1, reachable, shares, recovered, lateRecovered)
		previous = results
	}
}

type unstableConnectFixture struct {
	*smbFixture
	calls, failures int
}

func (b *unstableConnectFixture) dial(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	b.calls++
	if b.calls <= b.failures {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	}
	if !strings.HasSuffix(address, ":445") || timeout != 10*time.Second {
		return nil, fmt.Errorf("incorrect fixture dial settings")
	}
	b.dials++
	return &smbFixtureConn{fixture: b.smbFixture}, nil
}

func TestSMBRecoveryNeverRetriesConfiguredAuthentication(t *testing.T) {
	b := &unstableConnectFixture{smbFixture: newSMBFixture(), failures: 1}
	b.authError = errors.New("synthetic rejection")
	cfg := fixtureCredentials()
	cfg.Timeout = 10
	result := checkSMB(context.Background(), "192.0.2.10", cfg, b)
	if result.Error == "" || len(b.auth) != 2 || b.auth[0].user != cfg.Username || b.auth[1].user != "Guest" || result.ConnectionAttempts != 2 {
		t.Fatalf("recovery repeated credentials or hid the error: %+v auth=%v", result, b.auth)
	}
}

func TestSMBReportedDomainFailuresKeepCodeAndNeverRetryAccount(t *testing.T) {
	for code, name := range map[uint32]string{0xc0000192: "STATUS_NETLOGON_NOT_STARTED", 0xc000005e: "STATUS_NO_LOGON_SERVERS", 0xc000006d: "STATUS_LOGON_FAILURE"} {
		t.Run(name, func(t *testing.T) {
			b := newSMBFixture()
			b.authError = &smb2.ResponseError{Code: code}
			result := checkSMB(context.Background(), "192.0.2.10", fixtureCredentials(), b)
			if !result.Port445Open || result.EnumerationStatus != "Not attempted" || len(result.Shares) != 0 ||
				!strings.Contains(result.Error, name) || !strings.Contains(result.Error, fmt.Sprintf("0x%08x", code)) {
				t.Fatalf("server error mislabeled or hidden: %+v", result)
			}
			if len(b.auth) != 2 || b.auth[0].user != "fixture-user" || b.auth[1].user != "Guest" || b.auth[1].password != "" {
				t.Fatal("server failure retried provided credentials")
			}
		})
	}
}

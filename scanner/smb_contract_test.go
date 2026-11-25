package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
)

// These fixtures model successful authentication followed by authorization
// failures. They never connect to a server or submit a password to a domain.
func TestSMBHostnameUsesOnlyOptionalPostScanLookup(t *testing.T) {
	ip := "192.0.2.10"
	result := ScanResult{IP: ip, Port445Open: true, EnumerationStatus: "Complete"}
	enabled := ScanConfig{ResolveHostnames: true}
	calls := 0
	lookup := func(ctx context.Context, address string) ([]string, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if address != ip || !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("unbounded or misdirected hostname lookup")
		}
		return []string{"files.example.test."}, nil
	}
	ctx := context.Background()
	if name := smbHostname(ctx, enabled, result, lookup); name != "files.example.test" {
		t.Fatalf("unexpected name %q", name)
	}
	withoutName := func(context.Context, string) ([]string, error) { return nil, errors.New("no PTR") }
	if name := smbHostname(ctx, enabled, result, withoutName); name != "" {
		t.Fatalf("invented name %q", name)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_ = smbHostname(canceled, enabled, result, lookup)
	_ = smbHostname(ctx, ScanConfig{}, result, lookup)
	_ = smbHostname(ctx, ScanConfig{PortScanOnly: true, ResolveHostnames: true}, result, lookup)
	result.Port445Open = false
	_ = smbHostname(ctx, enabled, result, lookup)
	if calls != 1 {
		t.Fatalf("unexpected lookup count %d", calls)
	}
}

func TestSMBPermissionDenialsDoNotReauthenticate(t *testing.T) {
	for _, deniedAt := range []string{"mount", "read", "write"} {
		t.Run(deniedAt, func(t *testing.T) {
			b := newSMBFixture()
			for i := 0; i < 128; i++ {
				b.names = append(b.names, fmt.Sprintf("Team-%03d", i))
			}
			b.deniedAt = deniedAt
			cfg := fixtureCredentials()
			res := checkSMB(context.Background(), "192.0.2.10", cfg, b)
			if res.Status != "Authenticated" || res.CredentialSource != "Configured" || res.Error != "" || len(res.Shares) != len(b.names) {
				t.Fatalf("share denials lost enumeration: status=%s error=%s shares=%d", res.Status, res.Error, len(res.Shares))
			}
			if len(b.auth) != 1 || b.dials != 1 || b.auth[0] != (fixtureAuth{cfg.Username, cfg.Password, cfg.Domain, "192.0.2.10"}) {
				t.Fatal("permission denial changed credentials or caused another authentication")
			}
			for i, share := range res.Shares {
				if share.Name != b.names[i] || share.CanWrite || share.CanRead != (deniedAt == "write") {
					t.Fatalf("incorrect access result at index %d", i)
				}
			}
			if deniedAt != "write" && b.writeCalls != 0 {
				t.Fatal("write attempted after mount/read permission was denied")
			}
			if b.logoffs != 1 || !b.eventsEndWith("logoff", "close") {
				t.Fatal("SMB session was not logged off before closing its connection")
			}
		})
	}
}

func TestSMBMixedSharesPreserveNamesAndPermissions(t *testing.T) {
	b := newSMBFixture()
	b.names = []string{"IPC$", "Public", "Team #1 雪", "ReadOnly", "Denied", "ipc$"}
	b.access["ReadOnly"] = "write"
	b.access["Denied"] = "mount"
	res := checkSMB(context.Background(), "192.0.2.10", fixtureCredentials(), b)
	want := []ShareInfo{
		{Name: "Public", CanRead: true, CanWrite: true, ReadCheck: "Granted", WriteCheck: "Granted"},
		{Name: "Team #1 雪", CanRead: true, CanWrite: true, ReadCheck: "Granted", WriteCheck: "Granted"},
		{Name: "ReadOnly", CanRead: true, ReadCheck: "Granted", WriteCheck: "Denied"},
		{Name: "Denied", ReadCheck: "Denied", WriteCheck: "Denied"},
	}
	if !reflect.DeepEqual(res.Shares, want) || res.Error != "" || len(b.auth) != 1 {
		t.Fatalf("mixed share results changed: %+v", res.Shares)
	}
	if b.created != 2 || b.fileCloses != 2 || b.removed != 2 || len(res.Warnings) != 0 {
		t.Fatal("successful write probes were not closed and removed")
	}
	if !b.sessionContext || !b.shareContexts {
		t.Fatal("session/share operations lost their cancellation context")
	}
}

func TestSMBListingDeniedDoesNotRetryLogin(t *testing.T) {
	b := newSMBFixture()
	b.listError = &smb2.ResponseError{Code: 0xc0000022} // STATUS_ACCESS_DENIED
	res := checkSMB(context.Background(), "192.0.2.10", fixtureCredentials(), b)
	if !strings.Contains(res.Error, "Failed to list shares") || len(b.auth) != 1 || b.dials != 1 || len(res.Shares) != 0 {
		t.Fatal("enumeration denial was hidden, or triggered another login")
	}
}

func TestSMBRejectedPasswordIsNotAutomaticallyRetried(t *testing.T) {
	b := newSMBFixture()
	b.authError = errors.New("synthetic authentication rejection")
	res := checkSMB(context.Background(), "192.0.2.10", fixtureCredentials(), b)
	if len(b.auth) != 2 || b.auth[0].user != "fixture-user" || b.auth[1] != (fixtureAuth{user: "Guest", host: "192.0.2.10"}) {
		t.Fatal("provided account was retried, or existing Guest fallback borrowed its credentials")
	}
	if res.Error == "" || res.Status != "Error" || len(res.Shares) != 0 {
		t.Fatal("failed authentication became a successful SMB result")
	}
}

func TestSMBNoCredentialsDoNotBorrowDomainPassword(t *testing.T) {
	b := newSMBFixture()
	cfg := fixtureCredentials()
	cfg.Username = ""
	res := checkSMB(context.Background(), "192.0.2.10", cfg, b)
	if res.Status != "Guest Session" || res.CredentialSource != "Guest" || len(b.auth) != 1 || b.auth[0] != (fixtureAuth{user: "Guest", host: "192.0.2.10"}) {
		t.Fatal("guest path changed or inherited stray domain/password fields")
	}
}

func TestSMBSkippedAuthenticationPaths(t *testing.T) {
	for _, mode := range []string{"port-only", "cancelled", "connect-failed"} {
		t.Run(mode, func(t *testing.T) {
			b := newSMBFixture()
			cfg := fixtureCredentials()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "port-only":
				cfg.PortScanOnly = true
			case "cancelled":
				cancel()
			case "connect-failed":
				b.dialError = errors.New("synthetic connection failure")
			}
			res := checkSMB(ctx, "192.0.2.10", cfg, b)
			if len(b.auth) != 0 || len(res.Shares) != 0 {
				t.Fatal("unused authentication was attempted")
			}
			if mode == "port-only" && (!res.Port445Open || res.Error != "") {
				t.Fatal("port-only result changed")
			}
			if mode == "connect-failed" && (res.Port445Open || res.Error == "") {
				t.Fatal("connection failure was hidden")
			}
			if mode == "cancelled" && b.dials != 0 {
				t.Fatal("cancelled request connected")
			}
		})
	}
}

func fixtureCredentials() ScanConfig {
	return ScanConfig{Username: "fixture-user", Password: "fixture :/@% 雪", Domain: "EXAMPLE", Timeout: 3, Threads: 1}
}

type fixtureAuth struct{ user, password, domain, host string }

type smbFixture struct {
	mu                                                       sync.Mutex
	events                                                   []string
	auth                                                     []fixtureAuth
	dials, logoffs, writeCalls, created, fileCloses, removed int
	names                                                    []string
	types                                                    map[string]uint32
	access                                                   map[string]string
	deniedAt                                                 string
	dialError, authError, listError                          error
	ctx                                                      context.Context
	sessionContext, shareContexts                            bool
}

func newSMBFixture() *smbFixture {
	return &smbFixture{access: make(map[string]string), shareContexts: true}
}
func (b *smbFixture) event(s string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, s)
}
func (b *smbFixture) eventsEndWith(a, c string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.events)
	return n >= 2 && b.events[n-2] == a && b.events[n-1] == c
}
func (b *smbFixture) dial(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	if address != "192.0.2.10:445" || timeout != 3*time.Second {
		panic("dial settings changed")
	}
	b.dials++
	if b.dialError != nil {
		return nil, b.dialError
	}
	return &smbFixtureConn{fixture: b}, nil
}
func (b *smbFixture) authenticate(ctx context.Context, _ net.Conn, host string, init *smb2.NTLMInitiator) (smbSession, error) {
	b.auth = append(b.auth, fixtureAuth{init.User, init.Password, init.Domain, host})
	if b.authError != nil {
		return nil, b.authError
	}
	b.ctx = ctx
	return b, nil
}
func (b *smbFixture) WithContext(ctx context.Context) smbSession {
	b.sessionContext = b.sessionContext || ctx == b.ctx
	return b
}
func (b *smbFixture) Logoff() error { b.logoffs++; b.event("logoff"); return nil }
func (b *smbFixture) ListShares() ([]smbListedShare, error) {
	shares := fixtureListedShares(b.names)
	for i := range shares {
		shares[i].Type = b.types[shares[i].Name]
	}
	return shares, b.listError
}
func (b *smbFixture) Mount(name string) (smbShare, error) {
	denied := b.deniedAt
	if value, ok := b.access[name]; ok {
		denied = value
	}
	if name == "ADMIN$" || name == "C$" || denied == "mount" {
		return nil, &smb2.ResponseError{Code: 0xc0000022}
	}
	return &smbFixtureShare{fixture: b, deniedAt: denied}, nil
}

type smbFixtureShare struct {
	fixture  *smbFixture
	deniedAt string
}

func (s *smbFixtureShare) WithContext(ctx context.Context) smbShare {
	s.fixture.shareContexts = s.fixture.shareContexts && ctx == s.fixture.ctx
	return s
}
func (s *smbFixtureShare) Umount() error { return nil }
func (s *smbFixtureShare) ReadDir(path string) ([]os.FileInfo, error) {
	if path != "." {
		panic("read probe moved outside the share root")
	}
	if s.deniedAt == "read" {
		return nil, os.ErrPermission
	}
	return nil, nil
}
func (s *smbFixtureShare) OpenFile(name string, flags int, mode os.FileMode) (io.Closer, error) {
	s.fixture.writeCalls++
	if flags != os.O_RDWR|os.O_CREATE|os.O_EXCL || mode != 0600 {
		panic("write probe may overwrite an existing file")
	}
	if s.deniedAt == "write" {
		return nil, os.ErrPermission
	}
	s.fixture.created++
	return smbFixtureFile{s.fixture}, nil
}
func (s *smbFixtureShare) Remove(string) error { s.fixture.removed++; return nil }

type smbFixtureFile struct{ fixture *smbFixture }

func (f smbFixtureFile) Close() error { f.fixture.fileCloses++; return nil }

type smbFixtureConn struct{ fixture *smbFixture }

func (c *smbFixtureConn) Read([]byte) (int, error)       { panic("offline test attempted wire I/O") }
func (c *smbFixtureConn) Write([]byte) (int, error)      { panic("offline test attempted wire I/O") }
func (c *smbFixtureConn) Close() error                   { c.fixture.event("close"); return nil }
func (*smbFixtureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*smbFixtureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*smbFixtureConn) SetDeadline(time.Time) error      { return nil }
func (*smbFixtureConn) SetReadDeadline(time.Time) error  { return nil }
func (*smbFixtureConn) SetWriteDeadline(time.Time) error { return nil }

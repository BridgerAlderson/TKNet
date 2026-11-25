package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
)

func TestSMBCompletenessRetainsFullAndPartialEnumeration(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("partial=%t", partial), func(t *testing.T) {
			b := newCompletenessFixture()
			b.names = []string{"IPC$", "Public", "Hidden$", "Team 雪", "public", "ipc$"}
			if partial {
				b.listError = errors.New("next enumeration page failed")
			}
			res := checkSMB(context.Background(), "192.0.2.10", fixtureCredentials(), b)
			wantStatus := "Complete"
			if partial {
				wantStatus = "Partial"
			}
			if res.EnumerationStatus != wantStatus || (res.Error != "") != partial {
				t.Fatalf("enumeration state lost: %s, %s", res.EnumerationStatus, res.Error)
			}
			assertCompletenessNames(t, res, []string{"Public", "Hidden$", "Team 雪"})
			for _, share := range res.Shares {
				if !share.CanRead || !share.CanWrite || share.AccessError != "" {
					t.Fatalf("partial enumeration skipped checks of a known share: %+v", share)
				}
			}
			if len(b.auth) != 1 || b.logoffs != 1 || b.guardFailure != "" {
				t.Fatalf("authentication or operation guard changed: auth=%d logoff=%d guard=%s", len(b.auth), b.logoffs, b.guardFailure)
			}
		})
	}
}

func TestSMBCompletenessEnumerationPrecedesMetadataProbes(t *testing.T) {
	b := newCompletenessFixture()
	b.names = []string{"Public"}
	res := checkSMB(context.Background(), "192.0.2.10", fixtureCredentials(), b)
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	listIndex := -1
	for i, event := range b.trace {
		if event == "list" {
			listIndex = i
		}
		if strings.HasPrefix(event, "mount:") && listIndex < 0 {
			t.Fatalf("optional probe %q ran before share enumeration: %v", event, b.trace)
		}
	}
	if listIndex < 0 {
		t.Fatal("no enumeration was attempted")
	}
}

func TestSMBCompletenessTransportFailuresAreNotPermissionDenials(t *testing.T) {
	for _, stage := range []string{"mount", "read", "write"} {
		for _, denied := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/denied=%t", stage, denied), func(t *testing.T) {
				b := newCompletenessFixture()
				b.names = []string{"Troubled", "Healthy"}
				var failure error = &net.OpError{Op: stage, Net: "tcp", Err: os.ErrDeadlineExceeded}
				if denied {
					failure = &os.PathError{Op: stage, Path: "Troubled", Err: &smb2.ResponseError{Code: 0xc0000022}}
				}
				b.failures[stage+":Troubled"] = failure
				res := checkSMB(context.Background(), "192.0.2.10", fixtureCredentials(), b)
				assertCompletenessNames(t, res, b.names)
				got := res.Shares[0]
				if got.CanRead != (stage == "write") || got.CanWrite || (got.AccessError == "") != (denied && stage != "read") {
					t.Fatalf("transport failure became permission denial or changed observed rights: %+v", got)
				}
				if stage == "read" && (got.WriteCheck != "Not checked" || (got.ReadCheck == "Denied") != denied) {
					t.Fatalf("unattempted write was reported as a permission result: %+v", got)
				}
				if got := res.Shares[1]; !got.CanRead || !got.CanWrite || got.AccessError != "" {
					t.Fatalf("one failed check prevented the later healthy share: %+v", got)
				}
				if res.EnumerationStatus != "Complete" || len(b.auth) != 1 || b.dials != 1 || b.logoffs != 1 {
					t.Fatalf("check failure changed enumeration or retried login: %+v", res)
				}
				if b.guardFailure != "" {
					t.Fatal(b.guardFailure)
				}
			})
		}
	}
}

func TestSMBCompletenessCancellationRetainsKnownShares(t *testing.T) {
	for _, stage := range []string{"list-empty", "list", "mount:First", "read:First", "read:Last", "write:Last"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := newCompletenessFixture()
			b.names = []string{"First", "Last"}
			cancelAt := stage
			if stage == "list-empty" {
				b.names = nil
				cancelAt = "list"
			}
			b.onOperation = func(event string) {
				if event == cancelAt {
					cancel()
				}
			}
			res := checkSMB(ctx, "192.0.2.10", fixtureCredentials(), b)
			assertCompletenessNames(t, res, b.names)
			if res.Status != "Cancelled" || !strings.Contains(res.Error, "context canceled") {
				t.Fatalf("cancellation reported as completed authentication: status=%s error=%q", res.Status, res.Error)
			}
			if len(b.auth) != 1 || b.dials != 1 || b.logoffs != 1 {
				t.Fatalf("cancellation retried authentication or lost cleanup: auth=%d dials=%d logoffs=%d", len(b.auth), b.dials, b.logoffs)
			}
			if stage == "list" || stage == "list-empty" {
				for _, event := range b.trace {
					if strings.HasPrefix(event, "mount:") {
						t.Fatalf("metadata/access check started after enumeration cancellation: %s", event)
					}
				}
			}
			for _, share := range res.Shares {
				if !share.CanRead && share.AccessError == "" {
					t.Fatalf("cancelled/unvisited share presented as permission denial: %+v", share)
				}
			}
		})
	}
}

func TestSMBCompletenessGuestFallbackDisclosesLimitedIdentitySafely(t *testing.T) {
	b := newCompletenessFixture()
	cfg := fixtureCredentials()
	b.names = []string{"GuestVisible"}
	b.credentialError = fmt.Errorf("server sent account %s password %s", cfg.Username, cfg.Password)
	res := checkSMB(context.Background(), "192.0.2.10", cfg, b)
	if res.Status != "Guest Session" || res.EnumerationStatus != "Complete" || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "using Guest") || !strings.Contains(res.Warnings[0], "limited") {
		t.Fatalf("Guest fallback hid the changed identity/visibility: %+v", res)
	}
	if len(b.auth) != 2 || b.auth[1].user != "Guest" || b.auth[1].password != "" || b.auth[1].domain != "" {
		t.Fatal("fallback retried the configured identity or borrowed its secret")
	}
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{cfg.Username, cfg.Password, cfg.Domain} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("authentication diagnostics included configured credentials")
		}
	}
	if b.guardFailure != "" {
		t.Fatal(b.guardFailure)
	}
}

func TestSMBGuestFallbackDoesNotReuseRejectedCredentialsForWMI(t *testing.T) {
	b := newCompletenessFixture()
	cfg := fixtureCredentials()
	cfg.EnableWMI = true
	b.names = []string{"GuestVisible", "print$"}
	b.credentialError = &smb2.ResponseError{Code: 0xc000006d}
	res := checkSMB(context.Background(), "192.0.2.10", cfg, b)
	if res.Status != "Guest Session" || res.EnumerationStatus != "Complete" || len(res.Shares) != 2 {
		t.Fatalf("optional WMI changed the successful Guest enumeration: %+v", res)
	}
	if len(b.auth) != 2 || b.auth[0].user != cfg.Username || b.auth[1] != (fixtureAuth{user: "Guest", host: "192.0.2.10"}) {
		t.Fatal("configured credentials were retried or borrowed by Guest")
	}
	if res.WMIInfo != "" || len(res.Warnings) != 2 || !strings.Contains(res.Warnings[1], "WMI skipped: configured-account authentication failed") {
		t.Fatalf("WMI did not explicitly skip the rejected credentials: %+v", res.Warnings)
	}
}

func TestSMBCompletenessConnectAndProtocolBudgetsRemainSeparate(t *testing.T) {
	for _, timeout := range []int{1, 3, 10, 30, 31, 60} {
		t.Run(fmt.Sprintf("timeout=%d", timeout), func(t *testing.T) {
			b := newCompletenessFixture()
			b.names = []string{"Public"}
			cfg := fixtureCredentials()
			cfg.Timeout = timeout
			res := checkSMB(context.Background(), "192.0.2.10", cfg, b)
			if res.Error != "" || b.guardFailure != "" {
				t.Fatalf("scan failed: %s, guard=%s", res.Error, b.guardFailure)
			}
			if !reflect.DeepEqual(b.dialTimeouts, []time.Duration{time.Duration(timeout) * time.Second}) {
				t.Fatalf("connect timeout changed: %v", b.dialTimeouts)
			}
			if b.guarded.timeout != max(30*time.Second, time.Duration(timeout)*time.Second) || b.guarded.active != 0 {
				t.Fatalf("wrong protocol budget or leaked operation: timeout=%v active=%d", b.guarded.timeout, b.guarded.active)
			}
		})
	}
}

func TestSMBCompletenessDirectoryProbeIsBoundedAndCloses(t *testing.T) {
	for _, scenario := range []string{"entry", "empty", "denied", "timeout", "closed", "entry-and-eof"} {
		t.Run(scenario, func(t *testing.T) {
			directory := &completenessDirectory{}
			var wantError error
			switch scenario {
			case "entry":
				directory.entries = []os.FileInfo{nil}
			case "entry-and-eof":
				directory.entries, directory.err = []os.FileInfo{nil}, io.EOF
			case "empty":
				directory.err = io.EOF
			case "denied":
				directory.err, wantError = os.ErrPermission, os.ErrPermission
			case "timeout":
				directory.err, wantError = os.ErrDeadlineExceeded, os.ErrDeadlineExceeded
			case "closed":
				directory.err, wantError = os.ErrClosed, os.ErrClosed
			}
			entries, err := probeSMBDirectory(directory)
			if !errors.Is(err, wantError) || len(entries) != len(directory.entries) || !reflect.DeepEqual(directory.requests, []int{1}) || directory.closes != 1 {
				t.Fatalf("unbounded probe, wrong permission evidence or leaked handle: entries=%v err=%v requests=%v closes=%d", entries, err, directory.requests, directory.closes)
			}
		})
	}
}

func TestSMBCompletenessLogoffHasSeparateShortBudget(t *testing.T) {
	b := newCompletenessFixture()
	b.names = []string{"Public"}
	b.onOperation = func(event string) {
		if event != "logoff" {
			return
		}
		if len(b.contexts) != 2 {
			t.Fatalf("expected scan and cleanup contexts, got %d", len(b.contexts))
		}
		deadline, bounded := b.contexts[1].Deadline()
		if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 3*time.Second {
			t.Fatal("cleanup did not receive a separate short deadline")
		}
	}
	result := checkSMB(context.Background(), "192.0.2.10", fixtureCredentials(), b)
	if result.Error != "" || len(result.Shares) != 1 || b.logoffs != 1 ||
		b.contexts[1].Err() != context.Canceled || !b.eventsEndWith("logoff", "close") {
		t.Fatalf("cleanup changed the result, leaked a timer or closed out of order: %+v", result)
	}
}

func assertCompletenessNames(t *testing.T, result ScanResult, names []string) {
	t.Helper()
	got := make([]string, len(result.Shares))
	for i, share := range result.Shares {
		got[i] = share.Name
	}
	if len(got) != len(names) {
		t.Fatalf("known shares lost: got %v, want %v", got, names)
	}
	for i := range got {
		if got[i] != names[i] {
			t.Fatalf("known shares changed: got %v, want %v", got, names)
		}
	}
}

type completenessFixture struct {
	*smbFixture
	failures        map[string]error
	credentialError error
	guarded         *smbConnection
	guardFailure    string
	dialTimeouts    []time.Duration
	trace           []string
	onOperation     func(string)
	contexts        []context.Context
}

func newCompletenessFixture() *completenessFixture {
	return &completenessFixture{smbFixture: newSMBFixture(), failures: make(map[string]error)}
}
func (b *completenessFixture) observe(event string) {
	b.trace = append(b.trace, event)
	if b.guarded == nil {
		b.guardFailure = event + ": no guarded connection"
	} else {
		b.guarded.mu.Lock()
		if b.guarded.active == 0 {
			b.guardFailure = event + ": request was not inside an active operation"
		}
		b.guarded.mu.Unlock()
	}
	if b.onOperation != nil {
		b.onOperation(event)
	}
}
func (b *completenessFixture) dial(_ context.Context, address string, timeout time.Duration) (net.Conn, error) {
	if address != "192.0.2.10:445" {
		panic("unexpected test target")
	}
	b.dialTimeouts = append(b.dialTimeouts, timeout)
	b.dials++
	return &smbFixtureConn{fixture: b.smbFixture}, nil
}
func (b *completenessFixture) authenticate(ctx context.Context, conn net.Conn, host string, init *smb2.NTLMInitiator) (smbSession, error) {
	b.guarded, _ = conn.(*smbConnection)
	b.observe("authenticate")
	b.auth = append(b.auth, fixtureAuth{init.User, init.Password, init.Domain, host})
	if init.User != "Guest" && b.credentialError != nil {
		return nil, b.credentialError
	}
	b.ctx = ctx
	return b, nil
}
func (b *completenessFixture) WithContext(ctx context.Context) smbSession {
	b.contexts = append(b.contexts, ctx)
	b.smbFixture.WithContext(ctx)
	return b
}
func (b *completenessFixture) Logoff() error {
	b.observe("logoff")
	return b.smbFixture.Logoff()
}
func (b *completenessFixture) ListShares() ([]smbListedShare, error) {
	b.observe("list")
	if err := b.ctx.Err(); err != nil {
		return fixtureListedShares(b.names), err
	}
	return b.smbFixture.ListShares()
}
func (b *completenessFixture) Mount(name string) (smbShare, error) {
	b.observe("mount:" + name)
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}
	if err := b.failures["mount:"+name]; err != nil {
		return nil, err
	}
	share, err := b.smbFixture.Mount(name)
	if err != nil {
		return nil, err
	}
	return &completenessShare{smbShare: share, fixture: b, name: name}, nil
}

type completenessShare struct {
	smbShare
	fixture *completenessFixture
	name    string
}

func (s *completenessShare) WithContext(ctx context.Context) smbShare {
	s.smbShare = s.smbShare.WithContext(ctx)
	return s
}
func (s *completenessShare) Umount() error {
	s.fixture.observe("umount:" + s.name)
	return s.smbShare.Umount()
}
func (s *completenessShare) ReadDir(name string) ([]os.FileInfo, error) {
	s.fixture.observe("read:" + s.name)
	if err := s.fixture.ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.fixture.failures["read:"+s.name]; err != nil {
		return nil, err
	}
	return s.smbShare.ReadDir(name)
}
func (s *completenessShare) OpenFile(name string, flags int, mode os.FileMode) (io.Closer, error) {
	s.fixture.observe("write:" + s.name)
	if err := s.fixture.ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.fixture.failures["write:"+s.name]; err != nil {
		return nil, err
	}
	file, err := s.smbShare.OpenFile(name, flags, mode)
	if err != nil {
		return nil, err
	}
	return completenessFile{Closer: file, share: s}, nil
}
func (s *completenessShare) Remove(name string) error {
	s.fixture.observe("remove:" + s.name)
	return s.smbShare.Remove(name)
}

type completenessFile struct {
	io.Closer
	share *completenessShare
}

func (f completenessFile) Close() error {
	f.share.fixture.observe("close-file:" + f.share.name)
	return f.Closer.Close()
}

type completenessDirectory struct {
	entries  []os.FileInfo
	err      error
	requests []int
	closes   int
}

func (d *completenessDirectory) Readdir(count int) ([]os.FileInfo, error) {
	d.requests = append(d.requests, count)
	return d.entries, d.err
}
func (d *completenessDirectory) Close() error { d.closes++; return nil }

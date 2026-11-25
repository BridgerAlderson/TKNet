package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
)

// Optional interoperability test. tools/test_smb_loopback.py supplies an isolated
// server, synthetic credentials and temporary directories, all on loopback.
func TestSMBLoopbackInteroperability(t *testing.T) {
	address := os.Getenv("TKNET_TEST_SMB_ADDRESS")
	if address == "" {
		t.Skip("run tools/test_smb_loopback.py for the isolated SMB server")
	}
	host, port, err := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || host != "127.0.0.1" || number < 1024 {
		t.Fatal("fixture must use a loopback address and an unprivileged port")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	failConnections := 0
	if value := os.Getenv("TKNET_TEST_SMB_CONNECT_FAILURES"); value != "" {
		failConnections, err = strconv.Atoi(value)
		if err != nil || failConnections < 0 || failConnections > 2 {
			t.Fatal("connection fault count must be 0–2")
		}
	}
	b := &loopbackSMBBackend{address: address, failConnections: failConnections}
	result := checkSMB(ctx, host, ScanConfig{
		Username: "tknet-fixture", Password: "fixture-only-password", Domain: "LAB", Timeout: 3,
	}, b)
	partial := os.Getenv("TKNET_TEST_SMB_PARTIAL") == "1"
	wantCount, wantStatus := 134, "Complete"
	if partial {
		wantCount, wantStatus = 39, "Partial" // first RPC page includes IPC$
	}
	if result.Status != "Authenticated" || result.CredentialSource != "Configured" || result.EnumerationStatus != wantStatus ||
		len(result.Shares) != wantCount || (result.Error != "") != partial {
		t.Fatalf("SMB result: status=%s enumeration=%s shares=%d error=%s", result.Status, result.EnumerationStatus, len(result.Shares), result.Error)
	}
	if partial && !strings.Contains(result.Error, "Windows error 5") {
		t.Fatalf("partial result did not preserve the server's enumeration error: %s", result.Error)
	}
	names := make(map[string]bool)
	for _, share := range result.Shares {
		names[share.Name] = true
		if resourceType, ok := map[string]uint32{"OFFICE-PRINTER": 1, "LEGACY-DEVICE": 2, "SERVICE-PIPE": 3}[share.Name]; ok {
			if share.ShareType != resourceType || share.CanRead || share.CanWrite || share.AccessError != "" {
				t.Fatalf("non-file resource misclassified: %+v", share)
			}
			continue
		}
		if !share.CanRead || !share.CanWrite || share.AccessError != "" {
			t.Fatalf("incorrect permission result: %+v", share)
		}
	}
	for i := 0; i < min(wantCount, 128); i++ {
		if !names[fmt.Sprintf("SHARE-%03d", i)] {
			t.Fatalf("missing share %d", i)
		}
	}
	if !partial && (!names["HIDDEN$"] || !names["資料"] || !names["EMPTY"]) {
		t.Fatal("hidden, Unicode or empty-directory share was lost")
	}
	if !partial {
		for _, name := range []string{"OFFICE-PRINTER", "LEGACY-DEVICE", "SERVICE-PIPE"} {
			if !names[name] {
				t.Fatalf("non-file share dropped: %s", name)
			}
		}
	}
	if b.logins != 1 || b.connections != 1+failConnections || len(result.Warnings) != 0 ||
		result.ConnectionAttempts != 1+failConnections || len(result.ConnectionErrors) != failConnections {
		t.Fatalf("unexpected reconnect/login/warnings: connections=%d logins=%d warnings=%v", b.connections, b.logins, result.Warnings)
	}
	t.Logf("retained %d shares, %s enumeration, %d initial TCP attempts, one NTLM login, real SMB permission probes", len(result.Shares), strings.ToLower(wantStatus), result.ConnectionAttempts)
}

type loopbackSMBBackend struct {
	systemSMBBackend
	address         string
	logins          int
	connections     int
	failConnections int
}

func (b *loopbackSMBBackend) dial(ctx context.Context, _ string, timeout time.Duration) (net.Conn, error) {
	b.connections++
	if b.connections <= b.failConnections {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	}
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", b.address)
}

func (b *loopbackSMBBackend) authenticate(ctx context.Context, conn net.Conn, host string, initiator *smb2.NTLMInitiator) (smbSession, error) {
	b.logins++
	return b.systemSMBBackend.authenticate(ctx, conn, host, initiator)
}

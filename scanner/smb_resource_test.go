package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
)

func fixtureListedShares(names []string) []smbListedShare {
	shares := make([]smbListedShare, len(names))
	for i, name := range names {
		shares[i].Name = name
	}
	return shares
}

func fixtureListedNames(shares []smbListedShare) []string {
	names := make([]string, len(shares))
	for i, share := range shares {
		names[i] = share.Name
	}
	return names
}

func TestSMBWireShareTypesSurvivePagination(t *testing.T) {
	names := []string{"Data", "C$", "Cluster", "Temporary", "Ordinary name", "Device", "Pipe", "Future"}
	types := []uint32{0, 0x80000000, 0x0e000000, 0x40000000, 0x80000001, 2, 3, 0x7f}
	page := func(start, end int, resume, status uint32) []byte {
		p := fixtureSharePage(names[start:end], uint32(len(names)), resume, status)
		for i, value := range types[start:end] {
			smbRPCByteOrder.PutUint32(p[28+12*i:], value)
		}
		return p
	}
	p := fixturePipe(t, page(0, 4, 4, 234), page(4, 8, 0, 0))
	shares, err := enumerateSMBShares(p, "server")
	if err != nil || !reflect.DeepEqual(fixtureListedNames(shares), names) {
		t.Fatalf("lost shares: %v, %v", shares, err)
	}
	for i, share := range shares {
		if share.Type != types[i] {
			t.Fatalf("share type lost at %d: %#x", i, share.Type)
		}
	}
}

func TestSMBNonFileResourcesAreRetainedWithoutDirectoryProbes(t *testing.T) {
	b := newCompletenessFixture()
	b.names = []string{"Public", "Hidden$", "Cluster", "Printer", "Ordinary name", "Device", "Pipe", "Future"}
	b.types = map[string]uint32{"Hidden$": 0x80000000, "Cluster": 0x0e000000,
		"Printer": 1, "Ordinary name": 0x40000001, "Device": 2, "Pipe": 0x80000003, "Future": 0x7f}
	// A real disk-share read error must remain visible; it is not inferred to be
	// a printer from its name or its failure message.
	b.failures["read:Public"] = os.ErrNotExist
	result := checkSMB(context.Background(), "192.0.2.10", fixtureCredentials(), b)
	assertCompletenessNames(t, result, b.names)
	if result.EnumerationStatus != "Complete" || len(b.auth) != 1 {
		t.Fatalf("changed authentication/enumeration: %+v", result)
	}
	for i, share := range result.Shares {
		if share.ShareType != b.types[share.Name] {
			t.Fatal("server share type changed")
		}
		if i >= 3 {
			if share.FileAccessApplicable() || share.CanRead || share.CanWrite || share.AccessError != "" {
				t.Fatalf("fabricated file permissions/error: %+v", share)
			}
			for _, operation := range b.trace {
				if strings.HasSuffix(operation, ":"+share.Name) {
					t.Fatalf("non-file resource probed: %s", operation)
				}
			}
		} else if i == 0 {
			if !strings.Contains(share.AccessError, "file does not exist") {
				t.Fatal("genuine disk error hidden")
			}
		} else if !share.CanRead || !share.CanWrite || share.AccessError != "" {
			t.Fatalf("flagged disk share lost file checks: %+v", share)
		}
	}
	if b.created != 2 || b.removed != 2 {
		t.Fatalf("wrong disk write probes: %d/%d", b.created, b.removed)
	}
}

type closingEnumPipe struct {
	*enumFixturePipe
	closed bool
}

func (p *closingEnumPipe) Close() error { p.closed = true; return nil }

func TestSMBBusyEnumerationPipeRecoversAndEnumerates(t *testing.T) {
	for _, code := range []uint32{0xc00000ab, 0xc00000ac, 0xc00000ae} {
		t.Run(fmt.Sprintf("%08x", code), func(t *testing.T) {
			p := &closingEnumPipe{enumFixturePipe: fixturePipe(t, fixtureSharePage([]string{"Public", "Hidden$"}, 2, 0, 0))}
			calls := 0
			var delays []time.Duration
			pipe, err := openSMBEnumerationPipe(context.Background(), func() (io.ReadWriteCloser, error) {
				calls++
				if calls < 4 {
					return nil, &os.PathError{Op: "open", Path: "srvsvc", Err: &smb2.ResponseError{Code: code}}
				}
				return p, nil
			}, func(_ context.Context, d time.Duration) error { delays = append(delays, d); return nil })
			if err != nil || calls != 4 || !reflect.DeepEqual(delays, []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second}) {
				t.Fatalf("wrong bounded pipe recovery: %d, %v, %v", calls, delays, err)
			}
			shares, err := enumerateSMBShares(pipe, "server")
			_ = pipe.Close()
			if err != nil || len(shares) != 2 || !p.closed {
				t.Fatalf("recovered pipe lost enumeration/cleanup: %v, %v", shares, err)
			}
		})
	}
}

func TestSMBEnumerationPipeRetryBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		calls   int
	}{
		{"persistent busy", &smb2.ResponseError{Code: 0xc00000ac}, 4},
		{"access denied", &smb2.ResponseError{Code: 0xc0000022}, 1},
		{"logon rejected", &smb2.ResponseError{Code: 0xc000006d}, 1},
		{"unknown pipe", os.ErrNotExist, 1},
		{"transport closed", io.EOF, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			pipe, err := openSMBEnumerationPipe(context.Background(), func() (io.ReadWriteCloser, error) { calls++; return nil, tc.failure },
				func(context.Context, time.Duration) error { return nil })
			if pipe != nil || !errors.Is(err, tc.failure) || calls != tc.calls {
				t.Fatalf("wrong retry boundary: calls=%d err=%v", calls, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, err := openSMBEnumerationPipe(ctx, func() (io.ReadWriteCloser, error) { calls++; return nil, &smb2.ResponseError{Code: 0xc00000ac} },
		func(ctx context.Context, _ time.Duration) error { cancel(); return waitSMBConnect(ctx, time.Hour) })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancelled pipe wait issued another request")
	}
}

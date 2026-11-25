package netutil

import (
	"context"
	"github.com/gosnmp/gosnmp"
	"strings"
	"testing"
)

func TestSharePathsAreCredentialFreeAndEncoded(t *testing.T) {
	location, unc, err := shareLocations(`\\192.0.2.1\Team #1`)
	if err != nil || location != "smb://192.0.2.1/Team%20%231" || unc != `\\192.0.2.1\Team #1` {
		t.Fatalf("%q %q %v", location, unc, err)
	}
	for _, invalid := range []string{`\\user:secret@192.0.2.1\share`, `\\192.0.2.1\..`, `\\192.0.2.1\a\b`, `\\192.0.2.1\a/b`, `\\127.1\share`, "file:///tmp"} {
		if _, _, err := shareLocations(invalid); err == nil {
			t.Fatalf("invalid path accepted: %q", invalid)
		}
	}
}

func TestSpreadsheetText(t *testing.T) {
	for _, input := range []string{"=1+1", "+1", "-1", "@name", "  =1", "\tlabel", "\rlabel"} {
		if got := SpreadsheetText(input); got != "'"+input {
			t.Fatalf("unsafe cell %q", got)
		}
	}
	if SpreadsheetText("server-name") != "server-name" {
		t.Fatal("ordinary text changed")
	}
}

func TestSNMPRejectsCancelledAndInvalidRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := GetSNMPInfoContext(ctx, "not-an-address", "public", 1); err != context.Canceled {
		t.Fatalf("cancel ignored: %v", err)
	}
	for _, timeout := range []int{-1, 0, 61} {
		if _, err := GetSNMPInfoContext(context.Background(), "not-an-address", "public", timeout); err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("timeout validation missing: %v", err)
		}
	}
}

func TestSNMPMetadataAcceptsCanonicalAndDottedOIDs(t *testing.T) {
	for _, prefix := range []string{"", "."} {
		info, err := formatSNMPInfo([]gosnmp.SnmpPDU{
			{Name: prefix + "1.3.6.1.2.1.1.1.0", Value: []byte("Device\r\nDescription")},
			{Name: prefix + "1.3.6.1.2.1.1.5.0", Value: []byte("test-device")},
		})
		if err != nil || info != "[test-device] Device Description" {
			t.Fatalf("metadata lost: %q %v", info, err)
		}
	}
}

func TestSNMPResponseErrorsDoNotBecomeMetadata(t *testing.T) {
	variables := []gosnmp.SnmpPDU{{Name: "1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("Device description")}}
	for _, response := range []*gosnmp.SnmpPacket{
		nil,
		{Error: gosnmp.AuthorizationError, ErrorIndex: 1, Variables: variables},
		{Error: gosnmp.GenErr, Variables: variables},
		{Error: gosnmp.NoError, Variables: []gosnmp.SnmpPDU{{Name: "1.3.6.1.2.1.1.1.0", Type: gosnmp.NoSuchObject}}},
	} {
		if info, err := snmpResponseInfo(response); err == nil || info != "" {
			t.Fatalf("failed SNMP response reported metadata: %q %v", info, err)
		}
	}
	if info, err := snmpResponseInfo(&gosnmp.SnmpPacket{Variables: variables}); err != nil || info != "Device description" {
		t.Fatalf("valid SNMP metadata changed: %q %v", info, err)
	}
}

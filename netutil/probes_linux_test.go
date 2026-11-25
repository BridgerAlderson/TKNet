//go:build linux

package netutil

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxEchoRequiresTargetResponse(t *testing.T) {
	ip := net.ParseIP("192.0.2.5")
	for _, tt := range []struct {
		output string
		alive  bool
		rtt    uint32
	}{
		{"64 bytes from 192.0.2.5: icmp_seq=1 ttl=64 time=1.23 ms\n", true, 2},
		{"64 bytes from 192.0.2.5: icmp_seq=1 ttl=64 time<1 ms\n", true, 1},
		{"64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=1 ms\n", false, 0},
		{"From 192.0.2.1 icmp_seq=1 Destination Host Unreachable\n", false, 0},
		{"1 packets transmitted, 1 received, 0% packet loss", false, 0},
	} {
		got, rtt := parseLinuxPingReply(tt.output, ip)
		if got != tt.alive || rtt != tt.rtt {
			t.Errorf("%q => %t/%d", tt.output, got, rtt)
		}
	}
}
func TestARPRequiresMatchingReplyAndValidMAC(t *testing.T) {
	ip := net.ParseIP("192.0.2.5")
	for _, tt := range []struct {
		output string
		valid  bool
	}{
		{"Unicast reply from 192.0.2.5 [02:00:00:00:00:01] 1.000ms", true},
		{"42 bytes from 02:00:00:00:00:01 (192.0.2.5): index=0 time=1.000 msec", true},
		{"Unicast reply from 192.0.2.1 [02:00:00:00:00:01] 1.000ms", false},
		{"Unicast reply from 192.0.2.5 [FF:FF:FF:FF:FF:FF] 1.000ms", false},
		{"Unicast reply from 192.0.2.5 [00:00:00:00:00:00] 1.000ms", false},
		{"ARPING 192.0.2.5 [02:00:00:00:00:01]", false},
	} {
		_, got := parseARPReply(tt.output, ip)
		if got != tt.valid {
			t.Errorf("%q => %t", tt.output, got)
		}
	}
}
func TestPingToolUnavailableAndCancellation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	if alive, _, err := PingHostContext(context.Background(), net.ParseIP("127.0.0.1"), 100); alive || err == nil {
		t.Fatal("missing command became silent no-response")
	}
	script := []byte("#!/bin/sh\nexec /bin/sleep 10\n")
	if err := os.WriteFile(filepath.Join(dir, "ping"), script, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	alive, _, err := PingHostContext(ctx, net.ParseIP("127.0.0.1"), 5000)
	if alive || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("cancellation: %t %v %v", alive, err, time.Since(start))
	}
}

func TestArpingImplementations(t *testing.T) {
	for _, tt := range []struct{ help, flag string }{
		{"ARPing 2.28, by Thomas Habets\n [ -i <interface> ]", "-i"},
		{"Usage: arping [options] <destination>\n -I <device> interface name", "-I"},
	} {
		flag, err := arpingInterfaceFlag(tt.help)
		if err != nil || flag != tt.flag {
			t.Fatalf("help=%q flag=%q err=%v", tt.help, flag, err)
		}
	}
	if _, err := arpingInterfaceFlag("unknown"); err == nil {
		t.Fatal("guessed unsupported arping CLI")
	}
	if !arpToolFailure("arping: libnet_init(): UID/EUID 0 or capability CAP_NET_RAW required") {
		t.Fatal("permission error treated as no response")
	}
	if arpToolFailure("Sent 1 probes. Received 0 response(s)") {
		t.Fatal("normal no-response treated as tool failure")
	}
}

func TestARPInterfaceRespectsRouteSourceAndLinkType(t *testing.T) {
	subnet := func(s string) *net.IPNet {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	flags := net.FlagUp | net.FlagBroadcast
	links := []arpLink{
		{name: "eth0", flags: flags, addresses: []*net.IPNet{subnet("192.0.2.2/24")}},
		{name: "wifi0", flags: flags, addresses: []*net.IPNet{subnet("192.0.2.3/24")}},
		{name: "tun0", flags: net.FlagUp | net.FlagPointToPoint, addresses: []*net.IPNet{subnet("10.8.0.2/24")}},
	}
	for _, tt := range []struct{ target, source, want string }{
		{"192.0.2.8", "192.0.2.2", "eth0"},
		{"192.0.2.8", "192.0.2.3", "wifi0"},
		{"192.0.2.8", "10.8.0.2", ""},     // VPN route wins over a matching Ethernet subnet.
		{"198.51.100.8", "192.0.2.2", ""}, // Routed network.
		{"192.0.2.255", "192.0.2.2", ""},
		{"192.0.2.0", "192.0.2.2", ""},
		{"192.0.2.2", "192.0.2.2", ""},
	} {
		if got := chooseARPLink(net.ParseIP(tt.target), net.ParseIP(tt.source), links); got != tt.want {
			t.Errorf("%s via %s: got %q want %q", tt.target, tt.source, got, tt.want)
		}
	}
	links[0].flags = net.FlagBroadcast // Ethernet down.
	if got := chooseARPLink(net.ParseIP("192.0.2.8"), net.ParseIP("192.0.2.2"), links); got != "" {
		t.Fatal("selected down interface")
	}
}

func TestARPRouteParsing(t *testing.T) {
	route, err := parseARPRoute([]byte(`[{"dst":"192.0.2.8","dev":"tun0","prefsrc":"10.8.0.2","flags":[]}]`))
	if err != nil || route.Device != "tun0" || route.PrefSource != "10.8.0.2" {
		t.Fatalf("%+v %v", route, err)
	}
	route, err = parseARPRoute([]byte(`[{"dst":"192.0.2.8","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.2"}]`))
	if err != nil || route.Gateway == "" {
		t.Fatal("gateway information lost")
	}
	for _, input := range []string{`[]`, `[{},{}]`, `not json`} {
		if _, err := parseARPRoute([]byte(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

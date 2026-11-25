//go:build linux

package netutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ARPPing(ip net.IP) (bool, string, error) {
	return ARPPingContext(context.Background(), ip, time.Second)
}

// Only current arping replies are retained. /proc/net/arp contains stale entries
// and opening a UDP socket does not establish reachability. Even a fresh ARP
// reply can come from proxy ARP, so callers must not use it as sole alive proof.
func ARPPingContext(ctx context.Context, ip net.IP, timeout time.Duration) (bool, string, error) {
	if err := ctx.Err(); err != nil {
		return false, "", err
	}
	if ip.To4() == nil {
		return false, "", fmt.Errorf("ARP requires an IPv4 address")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	iface, err := arpInterface(ctx, ip)
	if err != nil {
		return false, "", err
	}
	if iface == "" {
		return false, "", nil
	}
	seconds := strconv.Itoa(int(math.Max(1, math.Ceil(timeout.Seconds()))))
	tool, err := arpingTool()
	if err != nil {
		return false, "", err
	}
	cmd := exec.CommandContext(ctx, tool.path, "-c", "1", "-w", seconds, tool.interfaceFlag, iface, ip.String())
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return false, "", ctx.Err()
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 && !arpToolFailure(string(output)) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("cannot run arping (check installation and ARP permissions): %w", err)
	}
	mac, ok := parseARPReply(string(output), ip)
	if !ok {
		return false, "", fmt.Errorf("arping returned no verifiable target reply")
	}
	return true, mac, nil
}

// Linux distributions ship two incompatible arping CLIs. Inspect help once,
// without transmitting a packet, instead of guessing the interface flag.
type arpCommand struct{ path, interfaceFlag string }

var arpingTool = sync.OnceValues(func() (arpCommand, error) {
	path, err := exec.LookPath("arping")
	if err != nil {
		return arpCommand{}, fmt.Errorf("arping is not installed: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-h")
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	output, _ := cmd.CombinedOutput()
	flag, err := arpingInterfaceFlag(string(output))
	return arpCommand{path, flag}, err
})

func arpingInterfaceFlag(help string) (string, error) {
	if strings.Contains(help, "Thomas Habets") {
		return "-i", nil
	}
	if strings.Contains(help, "-I ") {
		return "-I", nil
	}
	return "", fmt.Errorf("unsupported arping implementation; expected iputils or Thomas Habets arping")
}

func arpToolFailure(output string) bool {
	output = strings.ToLower(output)
	for _, marker := range []string{"permission denied", "operation not permitted", "must be root", "cap_net_raw", "invalid option", "no such device", "cannot", "failed"} {
		if strings.Contains(output, marker) {
			return true
		}
	}
	return false
}

// Query the kernel's chosen route, including gateway and device. Subnet
// membership or a source address alone is insufficient with VPN/policy routes.
// ip route get is a local routing-table lookup; it sends no discovery packets.
func arpInterface(ctx context.Context, target net.IP) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "-j", "-4", "route", "get", target.String())
	cmd.WaitDelay = 100 * time.Millisecond
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("cannot inspect route for ARP (iproute2 required): %w", err)
	}
	route, err := parseARPRoute(output)
	if err != nil {
		return "", err
	}
	if route.Gateway != "" || (route.Type != "" && route.Type != "unicast") {
		return "", nil
	}
	source := net.ParseIP(route.PrefSource)
	if source == nil {
		source = net.ParseIP(route.Source)
	}
	if source == nil || route.Device == "" {
		return "", fmt.Errorf("route has no usable source/interface for ARP")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	candidates := make([]arpLink, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Name != route.Device {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		link := arpLink{name: iface.Name, flags: iface.Flags}
		for _, addr := range addresses {
			if subnet, ok := addr.(*net.IPNet); ok {
				link.addresses = append(link.addresses, subnet)
			}
		}
		candidates = append(candidates, link)
	}
	return chooseARPLink(target, source, candidates), nil
}

type arpRoute struct {
	Gateway    string `json:"gateway"`
	Device     string `json:"dev"`
	PrefSource string `json:"prefsrc"`
	Source     string `json:"src"`
	Type       string `json:"type"`
}

func parseARPRoute(data []byte) (arpRoute, error) {
	var routes []arpRoute
	if err := json.Unmarshal(data, &routes); err != nil || len(routes) != 1 {
		return arpRoute{}, fmt.Errorf("ambiguous or invalid route response; ARP skipped")
	}
	return routes[0], nil
}

type arpLink struct {
	name      string
	flags     net.Flags
	addresses []*net.IPNet
}

func chooseARPLink(target, source net.IP, links []arpLink) string {
	selected := ""
	for _, link := range links {
		if link.flags&net.FlagUp == 0 || link.flags&net.FlagBroadcast == 0 || link.flags&net.FlagLoopback != 0 {
			continue
		}
		for _, subnet := range link.addresses {
			if !subnet.IP.Equal(source) || !subnet.Contains(target) || subnet.IP.Equal(target) {
				continue
			}
			ones, bits := subnet.Mask.Size()
			if bits != 32 {
				continue
			}
			if ones <= 30 {
				network := subnet.IP.Mask(subnet.Mask).To4()
				broadcast := append(net.IP(nil), network...)
				for i := range broadcast {
					broadcast[i] |= ^subnet.Mask[i]
				}
				if target.Equal(network) || target.Equal(broadcast) {
					continue
				}
			}
			if selected != "" && selected != link.name {
				return ""
			} // Ambiguous local addressing.
			selected = link.name
		}
	}
	return selected
}

var iputilsARPReply = regexp.MustCompile(`(?m)^(?:Unicast|Broadcast) reply from ([0-9.]+) \[([0-9A-Fa-f:]+)\]`)
var habetsARPReply = regexp.MustCompile(`(?m)^\d+ bytes from ([0-9A-Fa-f:]+) \(([0-9.]+)\): index=\d+ time=`)

func parseARPReply(output string, target net.IP) (string, bool) {
	for _, m := range iputilsARPReply.FindAllStringSubmatch(output, -1) {
		if net.ParseIP(m[1]).Equal(target) {
			if mac, ok := ValidMAC(m[2]); ok {
				return mac, true
			}
		}
	}
	for _, m := range habetsARPReply.FindAllStringSubmatch(output, -1) {
		if net.ParseIP(m[2]).Equal(target) {
			if mac, ok := ValidMAC(m[1]); ok {
				return mac, true
			}
		}
	}
	return "", false
}

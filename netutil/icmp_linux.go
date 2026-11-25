//go:build linux

package netutil

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

func PingHost(ip net.IP, timeoutMs uint32) (bool, uint32, error) {
	return PingHostContext(context.Background(), ip, timeoutMs)
}

// A successful process exit alone is insufficient: require an echo reply from
// the requested address. -n and LC_ALL=C keep parsing independent of DNS/locale.
func PingHostContext(ctx context.Context, ip net.IP, timeoutMs uint32) (bool, uint32, error) {
	if ip.To4() == nil {
		return false, 0, fmt.Errorf("not an IPv4 address: %s", ip)
	}
	if timeoutMs == 0 {
		return false, 0, fmt.Errorf("ICMP timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	seconds := strconv.Itoa(int(math.Ceil(float64(timeoutMs) / 1000)))
	cmd := exec.CommandContext(ctx, "ping", "-n", "-4", "-c", "1", "-W", seconds, ip.String())
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return false, 0, ctx.Err()
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("cannot run ping (check installation and ICMP permissions): %w", err)
	}
	alive, rtt := parseLinuxPingReply(string(output), ip)
	if !alive {
		return false, 0, fmt.Errorf("ping returned no verifiable echo reply")
	}
	return true, rtt, nil
}

var pingReply = regexp.MustCompile(`(?m)^\s*\d+ bytes from ([0-9.]+): icmp_seq=\d+ (?:ttl=\d+ )?time([=<])([0-9.]+) ms`)

func parseLinuxPingReply(output string, target net.IP) (bool, uint32) {
	for _, match := range pingReply.FindAllStringSubmatch(output, -1) {
		if !net.ParseIP(match[1]).Equal(target) {
			continue
		}
		value, err := strconv.ParseFloat(match[3], 64)
		if err == nil && value >= 0 && value <= math.MaxUint32 {
			return true, uint32(math.Ceil(value))
		}
	}
	return false, 0
}

func ConnectPing(ip net.IP, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

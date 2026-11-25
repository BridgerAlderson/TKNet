package netutil

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// ValidMAC rejects empty, broadcast, multicast and non-Ethernet addresses.
func ValidMAC(value string) (string, bool) {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return "", false
	}
	zero := true
	for _, b := range mac {
		if b != 0 {
			zero = false
		}
	}
	if zero {
		return "", false
	}
	return strings.ToUpper(mac.String()), true
}

func IsConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || (runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10061)))
}

func IsLocalProbeError(err error) bool {
	// Windows sockets use Winsock errors rather than Go's POSIX compatibility constants.
	if runtime.GOOS == "windows" {
		for _, code := range []syscall.Errno{10013, 10024, 10055, 10049, 10050} {
			if errors.Is(err, code) {
				return true
			}
		}
	}
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EADDRNOTAVAIL)
}

func probeTimeout(ctx context.Context, timeout time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		return time.Until(deadline)
	}
	return timeout
}

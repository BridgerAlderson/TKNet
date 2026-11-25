package netutil

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"
)

func TestSocketErrorClassification(t *testing.T) {
	if !IsConnectionRefused(fmt.Errorf("dial: %w", syscall.ECONNREFUSED)) {
		t.Fatal("wrapped refusal lost")
	}
	if IsConnectionRefused(syscall.ETIMEDOUT) {
		t.Fatal("timeout became refusal")
	}
	if !IsLocalProbeError(fmt.Errorf("dial: %w", syscall.EMFILE)) {
		t.Fatal("local resource exhaustion lost")
	}
	if runtime.GOOS == "windows" {
		if !IsConnectionRefused(syscall.Errno(10061)) {
			t.Fatal("Winsock refusal lost")
		}
		for _, code := range []syscall.Errno{10013, 10024, 10055, 10049, 10050} {
			if !IsLocalProbeError(code) {
				t.Fatalf("Winsock error %d lost", code)
			}
		}
	}
}

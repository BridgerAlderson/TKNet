//go:build windows

package netutil

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

var (
	modIphlpapi     = syscall.NewLazyDLL("iphlpapi.dll")
	procCreateFile  = modIphlpapi.NewProc("IcmpCreateFile")
	procSendEcho    = modIphlpapi.NewProc("IcmpSendEcho")
	procCloseHandle = modIphlpapi.NewProc("IcmpCloseHandle")
)

// PingHost sends an ICMP echo request using the Windows IcmpSendEcho API.
// This does NOT require administrator privileges — it uses iphlpapi.dll which
// internally communicates with the ICMP driver via DeviceIoControl.
//
// Returns (alive, roundTripTimeMs, error).
// A false return with nil error means the host did not respond (timeout).
func PingHost(ip net.IP, timeoutMs uint32) (bool, uint32, error) {
	return PingHostContext(context.Background(), ip, timeoutMs)
}

func PingHostContext(ctx context.Context, ip net.IP, timeoutMs uint32) (bool, uint32, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	timeout := probeTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	if timeout <= 0 {
		return false, 0, context.DeadlineExceeded
	}
	timeoutMs = uint32((timeout + time.Millisecond - 1) / time.Millisecond)
	ip4 := ip.To4()
	if ip4 == nil {
		return false, 0, fmt.Errorf("not an IPv4 address: %s", ip)
	}

	// Create ICMP handle
	handle, _, callErr := procCreateFile.Call()
	if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
		return false, 0, fmt.Errorf("IcmpCreateFile failed: %v", callErr)
	}
	defer procCloseHandle.Call(handle)

	// Convert IP to uint32 — IcmpSendEcho expects the address in network byte order
	// which on little-endian x86/x64 means the first octet is in the lowest byte
	dst := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24

	// Small echo payload; the OS correlates the echo identifier and sequence.
	sendData := []byte("TK")
	sendSize := uint16(len(sendData))

	// Reply buffer: must hold at least one ICMP_ECHO_REPLY structure + send data + 8 bytes
	// Using 256 bytes is more than sufficient
	replySize := uint32(256)
	replyBuf := make([]byte, replySize)

	ret, _, sendErr := procSendEcho.Call(
		handle,
		uintptr(dst),
		uintptr(unsafe.Pointer(&sendData[0])),
		uintptr(sendSize),
		0, // no IP_OPTION_INFORMATION
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(replySize),
		uintptr(timeoutMs),
	)

	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	if ret == 0 {
		// IP status codes describe no response/unreachable, not local failures.
		if code, ok := sendErr.(syscall.Errno); ok && code >= 11002 && code <= 11018 {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("IcmpSendEcho failed: %v", sendErr)
	}

	// Parse ICMP_ECHO_REPLY manually to avoid struct alignment issues.
	// Memory layout (first 12 bytes):
	//   [0:4]  Address       uint32  — responding IP
	//   [4:8]  Status        uint32  — 0 = IP_SUCCESS
	//   [8:12] RoundTripTime uint32  — milliseconds
	status := binary.LittleEndian.Uint32(replyBuf[4:8])
	rtt := binary.LittleEndian.Uint32(replyBuf[8:12])

	if status == 0 && net.IP(replyBuf[0:4]).Equal(ip4) { // IP_SUCCESS from target
		return true, rtt, nil
	}

	return false, 0, nil
}

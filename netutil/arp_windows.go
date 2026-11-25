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

// Windows IP Helper API (iphlpapi.dll)
var (
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	sendARP  = iphlpapi.NewProc("SendARP")
)

// ARPPing resolves a local address. SendARP may use the neighbor cache or a
// proxy response, so this is metadata and must never be sole liveness evidence.
func ARPPing(ip net.IP) (alive bool, macAddress string, err error) {
	return ARPPingContext(context.Background(), ip, time.Second)
}

// SendARP is synchronous and has an OS-controlled timeout. Cancellation is
// checked before/after the call; no abandoned goroutine or unsafe buffer remains.
func ARPPingContext(ctx context.Context, ip net.IP, timeout time.Duration) (alive bool, macAddress string, err error) {
	if err := ctx.Err(); err != nil {
		return false, "", err
	}
	// Convert IP to uint32 (network byte order)
	ip4 := ip.To4()
	if ip4 == nil {
		return false, "", fmt.Errorf("ARP requires an IPv4 address")
	}

	// IP address needs to be in little-endian format for SendARP (network byte order reversed)
	destIP := binary.LittleEndian.Uint32(ip4)

	// Buffer to receive the MAC address (6 bytes)
	var mac [2]uint32
	var macLen uint32 = 6

	// SendARP(DestIP, SrcIP, pMacAddr, PhyAddrLen)
	// Return value: NO_ERROR (0) if successful
	ret, _, _ := sendARP.Call(
		uintptr(destIP),
		0, // SrcIP: 0 means let the system choose
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if err := ctx.Err(); err != nil {
		return false, "", err
	}

	if ret == 0 && macLen == 6 {
		// Extract MAC bytes
		// mac[0] contains bytes 0-3, mac[1] contains bytes 4-5
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b[0:4], mac[0])
		binary.LittleEndian.PutUint32(b[4:8], mac[1])

		macStr := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
			b[0], b[1], b[2], b[3], b[4], b[5])

		if mac, valid := ValidMAC(macStr); valid {
			return true, mac, nil
		}
		return false, "", fmt.Errorf("SendARP returned an invalid hardware address")
	}

	if ret == 67 || ret == 31 {
		return false, "", nil
	}
	return false, "", fmt.Errorf("SendARP failed: %v", syscall.Errno(ret))
}

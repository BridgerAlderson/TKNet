//go:build linux

package netutil

import "fmt"

// GetWMIOSInfo is not supported on Linux — WMI is a Windows-only API.
func GetWMIOSInfo(ip, username, password, domain string) (string, error) {
	return "", fmt.Errorf("WMI is not available on Linux")
}

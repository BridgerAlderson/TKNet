//go:build windows

package netutil

import (
	"fmt"
	"strings"

	"github.com/yusufpapurcu/wmi"
)

// Win32_OperatingSystem holds WMI response data for OS info.
type Win32_OperatingSystem struct {
	Caption     string
	Version     string
	BuildNumber string
}

// GetWMIOSInfo queries the Win32_OperatingSystem class on the target IP using the provided credentials.
// If username/password are empty, it attempts to use the current context (useful for local network).
func GetWMIOSInfo(ip, username, password, domain string) (string, error) {
	var dst []Win32_OperatingSystem
	query := "SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem"

	// Format user for WMI
	user := username
	if domain != "" && user != "" {
		user = fmt.Sprintf("%s\\%s", domain, username)
	}

	var err error
	if user != "" && password != "" {
		// wmi.Query accepts connectServerArgs: server, namespace, user, password
		err = wmi.Query(query, &dst, ip, `root\cimv2`, user, password)
	} else {
		err = wmi.Query(query, &dst, ip)
	}

	if err != nil {
		return "", fmt.Errorf("WMI query failed: %w", err)
	}

	if len(dst) > 0 {
		os := dst[0]
		return fmt.Sprintf("%s | Build: %s", strings.TrimSpace(os.Caption), os.BuildNumber), nil
	}

	return "", fmt.Errorf("no OS info returned")
}

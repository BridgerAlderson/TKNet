package netutil

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// shareLocations only constructs paths. Credentials never enter a URL or argv.
func shareLocations(sharePath string) (string, string, error) {
	parts := strings.Split(strings.TrimPrefix(sharePath, `\\`), `\`)
	if len(parts) != 2 || !strings.HasPrefix(sharePath, `\\`) {
		return "", "", fmt.Errorf("expected an IPv4 UNC share path")
	}
	ip := net.ParseIP(parts[0])
	if ip == nil || ip.To4() == nil || ip.String() != parts[0] || parts[1] == "" || parts[1] == "." || parts[1] == ".." || strings.ContainsAny(parts[1], "/\x00\r\n") {
		return "", "", fmt.Errorf("invalid IPv4 share path")
	}
	u := url.URL{Scheme: "smb", Host: parts[0], Path: "/" + parts[1]}
	return u.String(), sharePath, nil
}

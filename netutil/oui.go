package netutil

import (
	"strings"
)

// Known MAC OUIs for common enterprise hardware and virtualization platforms.
// In a full production application, this could be loaded from an external ieee.txt file.
// For standalone executable constraints, we hardcode the most critical ones.
var ouiDB = map[string]string{
	// Virtualization
	"00:50:56": "VMware",
	"00:0C:29": "VMware",
	"00:05:69": "VMware",
	"00:15:5D": "Microsoft Hyper-V",
	"08:00:27": "Oracle VirtualBox",
	"52:54:00": "QEMU/KVM",
	"00:16:3E": "Xen",

	// Networking / Infrastructure
	"00:00:0C": "Cisco",
	"00:01:42": "Cisco",
	"00:01:43": "Cisco",
	"00:1B:D4": "Cisco",
	"00:04:F2": "Polycom",
	"00:08:5D": "Aastra",
	"00:0B:82": "Grandstream",
	"00:15:65": "Yealink",

	// PC / Server Manufacturers
	"00:11:11": "Intel",
	"00:1B:21": "Intel",
	"00:1A:4B": "Hewlett-Packard",
	"00:1E:0B": "Hewlett-Packard",
	"D4:AE:52": "Dell",
	"00:14:22": "Dell",
	"00:25:64": "Dell",
	"00:1A:A0": "Dell",
	"00:26:B9": "Dell",
	"B8:CA:3A": "Dell",
	"00:17:A4": "HP",
	"F0:92:1C": "Apple",
	"00:1D:4F": "Apple",
	"00:1E:C2": "Apple",
	"00:23:32": "Apple",
	"00:25:00": "Apple",
	"00:26:08": "Apple",
	
	// Security / Cameras
	"00:40:8C": "Axis Communications",
	"00:1A:07": "Cisco (Meraki)",
	"00:0B:86": "Aruba Networks",
	"44:19:B6": "Hikvision",
	"C4:2F:90": "Hikvision",

	// Storage / NAS
	"00:11:32": "Synology",
	"00:08:9B": "QNAP",
}

// GetMACVendor looks up the manufacturer for a given MAC address string (e.g., "00:50:56:C0:00:08").
func GetMACVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	
	// Extract the first 3 octets (e.g., "00:50:56")
	oui := strings.ToUpper(mac[:8])
	
	if vendor, ok := ouiDB[oui]; ok {
		return vendor
	}
	
	return "Unknown"
}

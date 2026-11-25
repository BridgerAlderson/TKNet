package ui

import (
	"encoding/csv"
	"fmt"
	"strings"
	"sync"
	"tknet/netutil"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"tknet/scanner"
)

var aliveColumnHeaders = []string{
	"#", "IP Address", "MAC Address", "Vendor", "Hostname", "Status",
	"ICMP", "TCP Ports", "NetBIOS", "DNS PTR", "Detection Method",
}

// AliveTable manages the Host Discovery results table.
type AliveTable struct {
	Table   *widget.Table
	mu      sync.RWMutex
	results []scanner.AliveResult
}

// NewAliveTable creates a new alive results table with sticky column headers.
func NewAliveTable() *AliveTable {
	at := &AliveTable{
		results: make([]scanner.AliveResult, 0),
	}

	at.Table = widget.NewTableWithHeaders(
		// Length: returns (rows, cols)
		func() (int, int) {
			at.mu.RLock()
			defer at.mu.RUnlock()
			return len(at.results), len(aliveColumnHeaders)
		},
		// CreateCell: returns a template widget for cell recycling
		func() fyne.CanvasObject {
			return widget.NewLabel("template content")
		},
		// UpdateCell: populates the cell with actual data
		func(id widget.TableCellID, o fyne.CanvasObject) {
			at.mu.RLock()
			defer at.mu.RUnlock()

			if id.Row >= len(at.results) {
				return
			}

			label := o.(*widget.Label)
			r := at.results[id.Row]

			switch id.Col {
			case 0: // #
				label.SetText(fmt.Sprintf("%d", id.Row+1))
			case 1: // IP Address
				label.SetText(r.IP)
			case 2: // MAC Address
				if r.MACAddress != "" {
					label.SetText(r.MACAddress)
				} else {
					label.SetText("—")
				}
			case 3: // Vendor
				if r.MACVendor != "" {
					label.SetText(r.MACVendor)
				} else {
					label.SetText("—")
				}
			case 4: // Hostname
				if r.Hostname != "" {
					label.SetText(r.Hostname)
				} else {
					label.SetText("—")
				}
			case 5: // Status
				if r.Status != "" {
					label.SetText(r.Status)
				} else if r.IsAlive {
					label.SetText("Confirmed")
				} else {
					label.SetText("No response")
				}
			case 6: // ICMP
				if r.ICMPAlive {
					label.SetText(r.ICMPLatency)
				} else {
					label.SetText("—")
				}
			case 7: // TCP Ports
				if len(r.TCPOpenPorts) > 0 {
					ports := make([]string, len(r.TCPOpenPorts))
					for i, p := range r.TCPOpenPorts {
						ports[i] = fmt.Sprintf("%d", p)
					}
					label.SetText(strings.Join(ports, ", "))
				} else {
					label.SetText("—")
				}
			case 8: // NetBIOS
				if r.NetBIOSAlive {
					label.SetText(r.NetBIOSName)
				} else {
					label.SetText("—")
				}
			case 9: // DNS PTR
				if r.DNSName != "" {
					label.SetText(r.DNSName)
				} else {
					label.SetText("—")
				}
			case 10: // Detection Method
				if r.DetectionMethod != "" {
					label.SetText(r.DetectionMethod)
				} else {
					label.SetText("—")
				}
			}
		},
	)

	// Configure sticky column headers
	at.Table.CreateHeader = func() fyne.CanvasObject {
		l := widget.NewLabel("")
		l.TextStyle = fyne.TextStyle{Bold: true}
		return l
	}
	at.Table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		label := o.(*widget.Label)
		if id.Row == -1 && id.Col >= 0 && id.Col < len(aliveColumnHeaders) {
			label.SetText(aliveColumnHeaders[id.Col])
		} else {
			label.SetText("")
		}
	}

	// Set column widths for readability (Compact to fit screen without scrolling)
	at.Table.SetColumnWidth(0, 35)   // #
	at.Table.SetColumnWidth(1, 110)  // IP Address
	at.Table.SetColumnWidth(2, 125)  // MAC Address
	at.Table.SetColumnWidth(3, 100)  // Vendor
	at.Table.SetColumnWidth(4, 130)  // Hostname
	at.Table.SetColumnWidth(5, 55)   // Status
	at.Table.SetColumnWidth(6, 60)   // ICMP
	at.Table.SetColumnWidth(7, 110)  // TCP Ports
	at.Table.SetColumnWidth(8, 90)   // NetBIOS
	at.Table.SetColumnWidth(9, 130)  // DNS PTR
	at.Table.SetColumnWidth(10, 115) // Detection Method

	return at
}

// AddResult appends a new discovery result to the table.
func (at *AliveTable) AddResult(r scanner.AliveResult) {
	at.mu.Lock()
	at.results = append(at.results, r)
	at.mu.Unlock()
	at.Table.Refresh()
}

// Clear removes all results from the table.
func (at *AliveTable) Clear() {
	at.mu.Lock()
	at.results = at.results[:0]
	at.mu.Unlock()
	at.Table.Refresh()
}

// GetAliveIPs returns only alive IPs as a newline-separated string.
func (at *AliveTable) GetAliveIPs() string {
	at.mu.RLock()
	defer at.mu.RUnlock()

	var ips []string
	for _, r := range at.results {
		if r.IsAlive {
			ips = append(ips, r.IP)
		}
	}
	return strings.Join(ips, "\n")
}

// GetAliveIPsWithHostnames returns alive IPs with their hostnames.
func (at *AliveTable) GetAliveIPsWithHostnames() string {
	at.mu.RLock()
	defer at.mu.RUnlock()

	var lines []string
	for _, r := range at.results {
		if r.IsAlive {
			hostname := r.Hostname
			if hostname == "" {
				hostname = "N/A"
			}
			lines = append(lines, fmt.Sprintf("%s - %s", r.IP, hostname))
		}
	}
	return strings.Join(lines, "\n")
}

// GetCSV returns all results as a CSV formatted string.
func (at *AliveTable) GetCSV() string {
	at.mu.RLock()
	defer at.mu.RUnlock()

	var sb strings.Builder
	w := csv.NewWriter(&sb)
	sb.WriteString("IP,MAC_Address,Vendor,Hostname,Status,ARP,ICMP,ICMP_Latency,TCP_Open_Ports,NetBIOS,NetBIOS_Name,DNS_PTR,Detection_Method\n")
	for _, r := range at.results {
		status := r.Status
		if status == "" {
			status = "No response"
		}
		if r.IsAlive {
			status = "Alive"
		}
		tcpPorts := ""
		if len(r.TCPOpenPorts) > 0 {
			ports := make([]string, len(r.TCPOpenPorts))
			for i, p := range r.TCPOpenPorts {
				ports[i] = fmt.Sprintf("%d", p)
			}
			tcpPorts = strings.Join(ports, ";")
		}
		dnsName := r.DNSName
		if dnsName == "" {
			dnsName = ""
		}
		nbName := r.NetBIOSName
		if nbName == "" {
			nbName = ""
		}
		macAddr := r.MACAddress
		if macAddr == "" {
			macAddr = ""
		}
		fields := []string{r.IP, macAddr, r.MACVendor, r.Hostname, status,
			fmt.Sprint(r.ARPAlive), fmt.Sprint(r.ICMPAlive), r.ICMPLatency,
			tcpPorts, fmt.Sprint(r.NetBIOSAlive), nbName, dnsName, r.DetectionMethod}
		for i := range fields {
			fields[i] = netutil.SpreadsheetText(fields[i])
		}
		_ = w.Write(fields)
	}
	w.Flush()
	return sb.String()
}

// Results returns a copy of all current results.
func (at *AliveTable) Results() []scanner.AliveResult {
	at.mu.RLock()
	defer at.mu.RUnlock()
	result := make([]scanner.AliveResult, len(at.results))
	copy(result, at.results)
	return result
}

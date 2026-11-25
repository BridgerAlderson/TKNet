package ui

import (
	"fmt"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"tknet/scanner"
)

var smbColumnHeaders = []string{
	"#", "IP Address", "Hostname", "Port 445", "OS Version", "SMB Version",
	"Admin Share", "Share Name", "Read", "Write",
}

// smbFlatRow represents a single flattened row in the SMB results table.
// Each share produces its own row; hosts with no shares get one row with empty share fields.
type smbFlatRow struct {
	ip           string
	hostname     string
	port445Open  bool
	smbVersion   string
	osVersion    string
	isAdmin      bool
	shareName    string
	canRead      bool
	canWrite     bool
	readUnknown  bool
	writeUnknown bool
	nonFileShare bool
	errorMsg     string
}

// SMBTable manages the SMB Scanner results table.
type SMBTable struct {
	Table    *widget.Table
	mu       sync.RWMutex
	results  []scanner.ScanResult
	flatRows []smbFlatRow

	// Callback triggered when a share is selected
	OnShareSelected func(ip, shareName string)
}

// NewSMBTable creates a new SMB results table with sticky column headers.
func NewSMBTable() *SMBTable {
	st := &SMBTable{
		results:  make([]scanner.ScanResult, 0),
		flatRows: make([]smbFlatRow, 0),
	}

	st.Table = widget.NewTableWithHeaders(
		// Length
		func() (int, int) {
			st.mu.RLock()
			defer st.mu.RUnlock()
			return len(st.flatRows), len(smbColumnHeaders)
		},
		// CreateCell
		func() fyne.CanvasObject {
			return widget.NewLabel("template content")
		},
		// UpdateCell
		func(id widget.TableCellID, o fyne.CanvasObject) {
			st.mu.RLock()
			defer st.mu.RUnlock()

			if id.Row >= len(st.flatRows) {
				return
			}

			label := o.(*widget.Label)
			r := st.flatRows[id.Row]

			switch id.Col {
			case 0: // #
				label.SetText(fmt.Sprintf("%d", id.Row+1))
			case 1: // IP Address
				label.SetText(r.ip)
			case 2: // Hostname
				if r.hostname != "" {
					label.SetText(r.hostname)
				} else {
					label.SetText("—")
				}
			case 3: // Port 445
				if r.port445Open {
					label.SetText("Open")
				} else {
					label.SetText("Closed")
				}
			case 4: // OS Version
				if r.osVersion != "" {
					label.SetText(r.osVersion)
				} else {
					label.SetText("—")
				}
			case 5: // SMB Version
				if r.smbVersion != "" {
					label.SetText(r.smbVersion)
				} else {
					label.SetText("—")
				}
			case 6: // Admin Priv
				if r.isAdmin {
					label.SetText("Accessible")
				} else {
					label.SetText("No")
				}
			case 7: // Share Name
				if r.shareName != "" {
					label.SetText(r.shareName)
				} else if r.errorMsg != "" {
					label.SetText(r.errorMsg)
				} else {
					label.SetText("—")
				}
			case 8: // Read
				if r.shareName == "" {
					label.SetText("—")
				} else if r.canRead {
					label.SetText("R")
				} else if r.readUnknown {
					label.SetText("?")
				} else {
					label.SetText("—")
				}
			case 9: // Write
				if r.shareName == "" {
					label.SetText("—")
				} else if r.canWrite {
					label.SetText("W")
				} else if r.writeUnknown {
					label.SetText("?")
				} else {
					label.SetText("—")
				}
			}
		},
	)

	// Configure sticky column headers
	st.Table.CreateHeader = func() fyne.CanvasObject {
		l := widget.NewLabel("")
		l.TextStyle = fyne.TextStyle{Bold: true}
		return l
	}
	st.Table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		label := o.(*widget.Label)
		if id.Row == -1 && id.Col >= 0 && id.Col < len(smbColumnHeaders) {
			label.SetText(smbColumnHeaders[id.Col])
		} else {
			label.SetText("")
		}
	}

	// Set column widths (Compact)
	st.Table.SetColumnWidth(0, 35)  // #
	st.Table.SetColumnWidth(1, 110) // IP Address
	st.Table.SetColumnWidth(2, 130) // Hostname
	st.Table.SetColumnWidth(3, 70)  // Port 445
	st.Table.SetColumnWidth(4, 150) // OS Version
	st.Table.SetColumnWidth(5, 90)  // SMB Version
	st.Table.SetColumnWidth(6, 80)  // Admin Priv
	st.Table.SetColumnWidth(7, 160) // Share Name
	st.Table.SetColumnWidth(8, 55)  // Read
	st.Table.SetColumnWidth(9, 55)  // Write

	// Handle row selection (click)
	st.Table.OnSelected = func(id widget.TableCellID) {
		st.Table.Unselect(id) // Immediately unselect so it can be clicked again

		st.mu.RLock()
		if id.Row < 0 || id.Row >= len(st.flatRows) {
			st.mu.RUnlock()
			return
		}
		row := st.flatRows[id.Row]
		st.mu.RUnlock()

		// Only trigger if a specific share is clicked
		if row.shareName != "" && !row.nonFileShare && st.OnShareSelected != nil {
			st.OnShareSelected(row.ip, row.shareName)
		}
	}

	return st
}

// appendFlatRows adds only the new host, avoiding a full rebuild for each result.
// Must be called while holding the write lock.
func (st *SMBTable) appendFlatRows(r scanner.ScanResult) {
	if len(r.Shares) == 0 {
		// Host with no shares (port closed, auth failed, etc.)
		st.flatRows = append(st.flatRows, smbFlatRow{
			ip:          r.IP,
			hostname:    r.Hostname,
			port445Open: r.Port445Open,
			osVersion:   r.OSVersion,
			smbVersion:  r.SMBVersion,
			isAdmin:     r.IsAdmin,
			errorMsg:    r.Error,
		})
	} else {
		// One row per share
		for _, share := range r.Shares {
			st.flatRows = append(st.flatRows, smbFlatRow{
				ip:           r.IP,
				hostname:     r.Hostname,
				port445Open:  r.Port445Open,
				osVersion:    r.OSVersion,
				smbVersion:   r.SMBVersion,
				isAdmin:      r.IsAdmin,
				shareName:    share.Name,
				canRead:      share.CanRead,
				canWrite:     share.CanWrite,
				readUnknown:  share.ReadCheck == "Not checked" || share.ReadCheck == "Inconclusive",
				writeUnknown: share.WriteCheck == "Not checked" || share.WriteCheck == "Inconclusive",
				nonFileShare: !share.FileAccessApplicable(),
			})
		}
	}
}

// AddResult appends a new SMB scan result and refreshes the table.
func (st *SMBTable) AddResult(r scanner.ScanResult) {
	st.mu.Lock()
	st.results = append(st.results, r)
	st.appendFlatRows(r)
	st.mu.Unlock()
	st.Table.Refresh()
}

// Clear removes all results from the table.
func (st *SMBTable) Clear() {
	st.mu.Lock()
	st.results = st.results[:0]
	st.flatRows = st.flatRows[:0]
	st.mu.Unlock()
	st.Table.Refresh()
}

// GetFlatRow returns the flat row at the given index, or nil if out of range.
func (st *SMBTable) GetFlatRow(index int) *smbFlatRow {
	st.mu.RLock()
	defer st.mu.RUnlock()

	if index < 0 || index >= len(st.flatRows) {
		return nil
	}
	row := st.flatRows[index]
	return &row
}

// Results returns a copy of all current scan results.
func (st *SMBTable) Results() []scanner.ScanResult {
	st.mu.RLock()
	defer st.mu.RUnlock()
	result := make([]scanner.ScanResult, len(st.results))
	copy(result, st.results)
	return result
}

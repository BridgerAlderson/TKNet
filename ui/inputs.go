package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// InputCallbacks holds callback functions triggered by UI actions.
type InputCallbacks struct {
	OnDiscover   func()
	OnSMBScan    func()
	OnStop       func()
	OnCopyIPs    func()
	OnCopyIPHost func()
	OnCopyCSV    func()
	OnSaveFile   func()
}

// InputPanel contains all left-side input widgets and action buttons.
type InputPanel struct {
	// Target input
	TargetEntry *widget.Entry

	// Credential state (Stored when dialog is saved)
	CurrentDomain   string
	CurrentUsername string
	CurrentPassword string
	CurrentUseHash  bool

	// Scan settings
	ThreadsEntry  *widget.Entry
	TimeoutEntry  *widget.Entry
	TCPPortsEntry *widget.Entry

	// Action buttons
	CredsBtn    *widget.Button
	DiscoverBtn *widget.Button
	SMBScanBtn  *widget.Button
	StopBtn     *widget.Button

	// Display for current credentials
	CredsLabel  *widget.Label

	// Progress indicator
	ProgressBar *widget.ProgressBar

	// The rendered, scrollable container
	Container fyne.CanvasObject
}

// NewInputPanel creates the left-side input panel with all widgets and callbacks wired.
func NewInputPanel(callbacks InputCallbacks) *InputPanel {
	ip := &InputPanel{}

	// ── Target Entry ──
	ip.TargetEntry = widget.NewMultiLineEntry()
	ip.TargetEntry.SetPlaceHolder("10.0.0.0/24\n192.168.1.0/24\n172.16.0.1")
	ip.TargetEntry.SetMinRowsVisible(5)

	// ── Credentials Button & Label ──
	ip.CredsLabel = widget.NewLabel("No credentials set.")
	ip.CredsLabel.TextStyle = fyne.TextStyle{Italic: true}
	
	// The CredsBtn action will be assigned in window.go because it needs access to the Window object to show the dialog
	ip.CredsBtn = widget.NewButton("Set Credentials", nil)
	
	credsVBox := container.NewVBox(ip.CredsBtn, ip.CredsLabel)
	credCard := widget.NewCard("Authentication", "For SMB scanning", container.NewPadded(credsVBox))

	// ── Scan Settings ──
	ip.ThreadsEntry = widget.NewEntry()
	ip.ThreadsEntry.SetText("10")

	ip.TimeoutEntry = widget.NewEntry()
	ip.TimeoutEntry.SetText("3")

	ip.TCPPortsEntry = widget.NewEntry()
	ip.TCPPortsEntry.SetText("22,80,135,443,445,3389,5985,8080,8443,139,53,88")

	// ── Action Buttons ──
	ip.DiscoverBtn = widget.NewButton("Discover Hosts", callbacks.OnDiscover)
	ip.DiscoverBtn.Importance = widget.HighImportance

	ip.SMBScanBtn = widget.NewButton("Scan SMB", callbacks.OnSMBScan)
	ip.SMBScanBtn.Importance = widget.HighImportance

	ip.StopBtn = widget.NewButton("Stop", callbacks.OnStop)
	ip.StopBtn.Importance = widget.DangerImportance
	ip.StopBtn.Disable()

	ip.ProgressBar = widget.NewProgressBar()

	// ── Copy / Export Buttons ──
	copyIPsBtn := widget.NewButton("Copy IPs", callbacks.OnCopyIPs)
	copyHostBtn := widget.NewButton("Copy IP:Hostname", callbacks.OnCopyIPHost)
	copyCSVBtn := widget.NewButton("Copy CSV", callbacks.OnCopyCSV)
	saveFileBtn := widget.NewButton("Save to File", callbacks.OnSaveFile)

	// ── Layout with Cards ──

	targetsCard := widget.NewCard("Targets", "CIDR or IP list", ip.TargetEntry)

	settingsForm := widget.NewForm(
		widget.NewFormItem("Threads", ip.ThreadsEntry),
		widget.NewFormItem("Timeout (sec)", ip.TimeoutEntry),
		widget.NewFormItem("TCP Ports", ip.TCPPortsEntry),
		widget.NewFormItem("Enable ARP", widget.NewLabel("(Always Enabled for Local Subnets)")),
	)
	settingsCard := widget.NewCard("Scan Settings", "", settingsForm)

	actionsBox := container.NewVBox(
		ip.DiscoverBtn,
		ip.SMBScanBtn,
		ip.StopBtn,
		ip.ProgressBar,
	)
	actionsCard := widget.NewCard("Operations", "Start or Stop Scans", container.NewPadded(actionsBox))

	copyBox := container.NewVBox(
		copyIPsBtn,
		copyHostBtn,
		copyCSVBtn,
		saveFileBtn,
	)
	copyCard := widget.NewCard("Copy / Export", "Extract results", container.NewPadded(copyBox))

	// ── Assemble into scrollable panel ──
	panel := container.NewVBox(
		container.NewPadded(targetsCard),
		container.NewPadded(credCard),
		container.NewPadded(settingsCard),
		container.NewPadded(actionsCard),
		container.NewPadded(copyCard),
	)

	// Wrap the entire scrollable area with additional padding so it doesn't hug the left edge
	ip.Container = container.NewPadded(container.NewVScroll(panel))

	return ip
}

// SetProgress updates the progress bar value (0.0 to 1.0).
func (ip *InputPanel) SetProgress(value float64) {
	ip.ProgressBar.SetValue(value)
}

// SetScanning toggles button states between scanning and idle modes.
func (ip *InputPanel) SetScanning(active bool) {
	if active {
		ip.DiscoverBtn.Disable()
		ip.SMBScanBtn.Disable()
		ip.StopBtn.Enable()
	} else {
		ip.DiscoverBtn.Enable()
		ip.SMBScanBtn.Enable()
		ip.StopBtn.Disable()
		ip.ProgressBar.SetValue(0)
	}
}

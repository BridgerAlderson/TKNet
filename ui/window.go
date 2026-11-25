package ui

import (
	"fmt"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"tknet/netutil"
	"tknet/scanner"
)

// MainWindow is the primary application window that orchestrates all UI components.
type MainWindow struct {
	App        fyne.App
	Window     fyne.Window
	InputPanel *InputPanel
	AliveTable *AliveTable
	SMBTable   *SMBTable
	LogPanel   *LogPanel
	Tabs       *container.AppTabs

	Engine *scanner.Engine
}

// NewMainWindow creates and configures the main application window.
func NewMainWindow(a fyne.App) *MainWindow {
	mw := &MainWindow{
		App:    a,
		Engine: scanner.NewEngine(),
	}

	mw.Window = a.NewWindow("TKNet — Network Recon & SMB Scanner")

	// Initialize components
	mw.LogPanel = NewLogPanel()
	mw.AliveTable = NewAliveTable()
	mw.SMBTable = NewSMBTable()

	// Wire SMB Table click handler
	mw.SMBTable.OnShareSelected = mw.onShareSelected

	// Wire callbacks and create input panel
	callbacks := InputCallbacks{
		OnDiscover:   mw.onDiscoverClick,
		OnSMBScan:    mw.onSMBScanClick,
		OnStop:       mw.onStopClick,
		OnCopyIPs:    mw.onCopyIPs,
		OnCopyIPHost: mw.onCopyIPHost,
		OnCopyCSV:    mw.onCopyCSV,
		OnSaveFile:   mw.onSaveFile,
	}
	mw.InputPanel = NewInputPanel(callbacks)

	// Create tabbed center area
	mw.Tabs = container.NewAppTabs(
		container.NewTabItem("Host Discovery", mw.AliveTable.Table),
		container.NewTabItem("SMB Scanner", mw.SMBTable.Table),
	)
	mw.Tabs.SetTabLocation(container.TabLocationTop)

	// Setup Credentials Button Logic
	mw.InputPanel.CredsBtn.OnTapped = mw.showCredentialsDialog

	// Main layout: Left = Inputs, Right = Tabs over LogPanel
	rightSide := container.NewBorder(
		nil,
		mw.LogPanel.Entry, // bottom
		nil,
		nil,
		mw.Tabs, // center
	)

	// Splitter to allow resizing the left panel
	split := container.NewHSplit(mw.InputPanel.Container, rightSide)
	split.Offset = 0.27 // Set to 27% (more solid, less wide) to leave maximum space for table

	mw.Window.SetContent(split)
	mw.Window.Resize(fyne.NewSize(1280, 750))
	mw.Window.CenterOnScreen()
	mw.Window.SetOnClosed(func() { mw.Engine.Stop() })

	mw.LogPanel.AddLog("TKNet started. Ready to scan.")

	return mw
}

// ShowAndRun displays the window and starts the Fyne event loop (blocking).
func (mw *MainWindow) ShowAndRun() {
	mw.Window.ShowAndRun()
}

// showCredentialsDialog opens a pop-up modal to set authentication details.
func (mw *MainWindow) showCredentialsDialog() {
	domainEntry := widget.NewEntry()
	domainEntry.SetText(mw.InputPanel.CurrentDomain)
	domainEntry.SetPlaceHolder("CONTOSO")

	usernameEntry := widget.NewEntry()
	usernameEntry.SetText(mw.InputPanel.CurrentUsername)
	usernameEntry.SetPlaceHolder("administrator")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetText(mw.InputPanel.CurrentPassword)

	authTypeSelect := widget.NewSelect(
		[]string{"Password", "NTLM Hash"},
		func(value string) {
			if value == "NTLM Hash" {
				passwordEntry.SetPlaceHolder("aad3b435b51404eeaad3b435b51404ee")
			} else {
				passwordEntry.SetPlaceHolder("password")
			}
		},
	)

	if mw.InputPanel.CurrentUseHash {
		authTypeSelect.SetSelected("NTLM Hash")
	} else {
		authTypeSelect.SetSelected("Password")
	}

	form := widget.NewForm(
		widget.NewFormItem("Domain", domainEntry),
		widget.NewFormItem("Username", usernameEntry),
		widget.NewFormItem("Password", passwordEntry),
		widget.NewFormItem("Auth Type", authTypeSelect),
	)

	dialog.ShowCustomConfirm("Set Authentication", "Save", "Cancel", container.NewPadded(form), func(saved bool) {
		if saved {
			mw.InputPanel.CurrentDomain = domainEntry.Text
			mw.InputPanel.CurrentUsername = usernameEntry.Text
			mw.InputPanel.CurrentPassword = passwordEntry.Text
			mw.InputPanel.CurrentUseHash = authTypeSelect.Selected == "NTLM Hash"

			// Update label to show active credential
			if mw.InputPanel.CurrentUsername != "" {
				displayDomain := mw.InputPanel.CurrentDomain
				if displayDomain == "" {
					displayDomain = "Local"
				}
				authTypeStr := "[PWD]"
				if mw.InputPanel.CurrentUseHash {
					authTypeStr = "[HASH]"
				}
				mw.InputPanel.CredsLabel.SetText(fmt.Sprintf("%s %s\\%s", authTypeStr, displayDomain, mw.InputPanel.CurrentUsername))
			} else {
				mw.InputPanel.CredsLabel.SetText("No credentials set.")
			}
			mw.LogPanel.AddLog("Credentials updated.")
		}
	}, mw.Window)
}

// ──────────────────────────────────────────────────────────────
//  Scan actions
// ──────────────────────────────────────────────────────────────

func (mw *MainWindow) onDiscoverClick() {
	targets := mw.InputPanel.TargetEntry.Text
	if strings.TrimSpace(targets) == "" {
		dialog.ShowInformation("Warning", "Please enter target IP/CIDR.", mw.Window)
		return
	}

	threads, err := strconv.Atoi(mw.InputPanel.ThreadsEntry.Text)
	if err != nil || threads < 1 {
		threads = 10
	}

	timeout, err := strconv.Atoi(mw.InputPanel.TimeoutEntry.Text)
	if err != nil || timeout < 1 {
		timeout = 3
	}

	// Parse TCP ports
	portStrs := strings.Split(mw.InputPanel.TCPPortsEntry.Text, ",")
	var ports []int
	for _, ps := range portStrs {
		p, err := strconv.Atoi(strings.TrimSpace(ps))
		if err == nil && p > 0 && p <= 65535 {
			ports = append(ports, p)
		}
	}

	cfg := scanner.AliveConfig{
		Targets:       targets,
		Threads:       threads,
		Timeout:       timeout,
		EnableICMP:    true,
		EnableTCP:     true,
		EnableNetBIOS: true,
		EnableDNS:     true,
		EnableARP:     true,
		TCPPorts:      ports,
	}

	mw.LogPanel.Clear()
	mw.AliveTable.Clear()
	mw.InputPanel.SetScanning(true)
	mw.Tabs.SelectIndex(0) // Switch to Host Discovery tab

	// Recreate engine channels if needed
	mw.Engine = scanner.NewEngine()

	// Start reading from channels in background
	go mw.handleEngineEvents(mw.Engine, true)

	mw.Engine.StartAliveDiscovery(cfg)
}

func (mw *MainWindow) handleEngineEvents(engine *scanner.Engine, isAlive bool) {
	logs, progress := engine.LogChan, engine.ProgressChan
	var alive <-chan scanner.AliveResult
	var smb <-chan scanner.ScanResult
	if isAlive {
		alive = engine.AliveResults
	} else {
		smb = engine.ScanResults
	}
	post := func(update func()) {
		fyne.Do(func() {
			if mw.Engine == engine {
				update()
			}
		})
	}
	for logs != nil || progress != nil || alive != nil || smb != nil {
		select {
		case message, ok := <-logs:
			if !ok {
				logs = nil
				continue
			}
			post(func() { mw.LogPanel.AddLog(message) })
		case value, ok := <-progress:
			if !ok {
				progress = nil
				continue
			}
			post(func() { mw.InputPanel.SetProgress(value) })
		case result, ok := <-alive:
			if !ok {
				alive = nil
				continue
			}
			post(func() { mw.AliveTable.AddResult(result) })
		case result, ok := <-smb:
			if !ok {
				smb = nil
				continue
			}
			post(func() { mw.SMBTable.AddResult(result) })
		}
	}
	post(func() { mw.InputPanel.SetScanning(false) })
}

func (mw *MainWindow) onSMBScanClick() {
	targets := mw.InputPanel.TargetEntry.Text
	if strings.TrimSpace(targets) == "" {
		dialog.ShowInformation("Warning", "Please enter target IP/CIDR.", mw.Window)
		return
	}
	username := mw.InputPanel.CurrentUsername
	if strings.TrimSpace(username) == "" {
		dialog.ShowInformation("Warning", "Username is required for SMB scan. Please set Credentials first.", mw.Window)
		return
	}

	password := mw.InputPanel.CurrentPassword
	domain := mw.InputPanel.CurrentDomain
	useHash := mw.InputPanel.CurrentUseHash

	threads, err := strconv.Atoi(mw.InputPanel.ThreadsEntry.Text)
	if err != nil || threads < 1 {
		threads = 10
	}

	timeout, err := strconv.Atoi(mw.InputPanel.TimeoutEntry.Text)
	if err != nil || timeout < 1 {
		timeout = 3
	}

	cfg := scanner.ScanConfig{
		Targets:      targets,
		Username:     username,
		Password:     password,
		Domain:       domain,
		UseHash:      useHash,
		Threads:      threads,
		Timeout:      timeout,
		PortScanOnly: false,
	}

	mw.LogPanel.Clear()
	mw.SMBTable.Clear()
	mw.InputPanel.SetScanning(true)
	mw.Tabs.SelectIndex(1) // Switch to SMB Scanner tab

	// Recreate engine channels if needed
	mw.Engine = scanner.NewEngine()

	// Start reading from channels in background
	go mw.handleEngineEvents(mw.Engine, false)

	mw.Engine.StartSMBScan(cfg)
}

func (mw *MainWindow) onStopClick() {
	mw.LogPanel.AddLog("Stop signal sent...")
	mw.Engine.Stop()
	mw.InputPanel.SetScanning(false)
}

func (mw *MainWindow) onCopyIPs() {
	content := mw.AliveTable.GetAliveIPs()
	if content == "" {
		mw.LogPanel.AddLog("No alive IPs found to copy.")
		return
	}
	mw.Window.Clipboard().SetContent(content)
	count := len(strings.Split(content, "\n"))
	mw.LogPanel.AddLog(fmt.Sprintf("%d alive IPs copied to clipboard.", count))
}

func (mw *MainWindow) onCopyIPHost() {
	content := mw.AliveTable.GetAliveIPsWithHostnames()
	if content == "" {
		mw.LogPanel.AddLog("No alive IPs found to copy.")
		return
	}
	mw.Window.Clipboard().SetContent(content)
	count := len(strings.Split(content, "\n"))
	mw.LogPanel.AddLog(fmt.Sprintf("%d alive IP:Hostnames copied to clipboard.", count))
}

func (mw *MainWindow) onCopyCSV() {
	content := mw.AliveTable.GetCSV()
	mw.Window.Clipboard().SetContent(content)
	mw.LogPanel.AddLog("CSV data copied to clipboard.")
}

func (mw *MainWindow) onSaveFile() {
	content := mw.AliveTable.GetCSV()
	if content == "" {
		dialog.ShowInformation("Error", "No data to save.", mw.Window)
		return
	}

	fd := dialog.NewFileSave(func(uc fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, mw.Window)
			return
		}
		if uc == nil {
			return // User cancelled
		}
		defer uc.Close()

		_, err = uc.Write([]byte(content))
		if err != nil {
			dialog.ShowError(err, mw.Window)
		} else {
			mw.LogPanel.AddLog(fmt.Sprintf("Data saved to %s.", uc.URI().Path()))
		}
	}, mw.Window)

	fd.SetFilter(storage.NewExtensionFileFilter([]string{".csv"}))
	fd.SetFileName("tknet_export.csv")
	fd.Show()
}

func (mw *MainWindow) onShareSelected(ip, shareName string) {
	sharePath := fmt.Sprintf(`\\%s\%s`, ip, shareName)

	dialog.ShowConfirm(
		"Open in Explorer",
		fmt.Sprintf("Do you want to open %s in Windows Explorer?", sharePath),
		func(confirm bool) {
			if !confirm {
				return
			}

			mw.LogPanel.AddLog(fmt.Sprintf("Opening %s...", sharePath))

			username := mw.InputPanel.CurrentUsername
			password := mw.InputPanel.CurrentPassword
			domain := mw.InputPanel.CurrentDomain
			useHash := mw.InputPanel.CurrentUseHash

			err := netutil.OpenShareInExplorer(sharePath, domain, username, password, useHash)
			if err != nil {
				dialog.ShowError(err, mw.Window)
				mw.LogPanel.AddLog(fmt.Sprintf("ERROR: %v", err))
			} else {
				mw.LogPanel.AddLog(fmt.Sprintf("Successfully opened: %s", sharePath))
			}
		},
		mw.Window,
	)
}

// --- END OF FILE ---

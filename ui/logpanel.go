package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2/widget"
)

const maxLogLines = 500

// LogPanel provides a read-only, scrollable log display at the bottom of the window.
type LogPanel struct {
	Entry *widget.Entry
	mu    sync.Mutex
	lines []string
}

// NewLogPanel creates a new log panel.
func NewLogPanel() *LogPanel {
	entry := widget.NewMultiLineEntry()
	entry.Disable() // Read-only
	entry.SetPlaceHolder("Log mesajlari burada gorunecek...")
	entry.SetMinRowsVisible(5)

	return &LogPanel{
		Entry: entry,
		lines: make([]string, 0, maxLogLines),
	}
}

// AddLog appends a timestamped message to the log panel.
func (lp *LogPanel) AddLog(msg string) {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	timestamp := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] %s", timestamp, msg)
	lp.lines = append(lp.lines, line)

	// Trim oldest lines if exceeding max capacity
	if len(lp.lines) > maxLogLines {
		lp.lines = lp.lines[len(lp.lines)-maxLogLines:]
	}

	lp.Entry.SetText(strings.Join(lp.lines, "\n"))
}

// Clear removes all log messages.
func (lp *LogPanel) Clear() {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	lp.lines = lp.lines[:0]
	lp.Entry.SetText("")
}

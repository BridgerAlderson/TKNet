package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"tknet/scanner"
)

type EngineRequest struct {
	Command     string              `json:"command"` // "alive" or "smb"
	AliveConfig scanner.AliveConfig `json:"alive_config"`
	ScanConfig  scanner.ScanConfig  `json:"scan_config"`
}

type EngineEvent struct {
	Type string      `json:"type"` // "log", "progress", "alive_result", "smb_result", "done"
	Data interface{} `json:"data"`
}

var emitMu sync.Mutex

func emit(eventType string, data interface{}) {
	emitMu.Lock()
	defer emitMu.Unlock()
	evt := EngineEvent{Type: eventType, Data: data}
	b, _ := json.Marshal(evt)
	fmt.Println(string(b))
}

func main() {
	isHeadless := false
	for _, arg := range os.Args {
		if arg == "--headless" {
			isHeadless = true
			break
		}
	}

	if !isHeadless {
		fmt.Println("Error: Engine must be run with --headless. GUI is in TKNetUI (C# Avalonia).")
		os.Exit(1)
	}

	scannerStdin := bufio.NewScanner(os.Stdin)
	// The desktop accepts 1 Mi UTF-16 characters of scope text. Its JSON
	// encoder may use six bytes per character (\uXXXX); allow that plus the
	// remaining settings while retaining a bounded request size.
	scannerStdin.Buffer(make([]byte, 4096), 8*1024*1024)
	var input string
	for scannerStdin.Scan() {
		input += scannerStdin.Text()
		break
	}

	if err := scannerStdin.Err(); err != nil {
		emit("error", fmt.Sprintf("Failed to read request: %v", err))
		emit("done", nil)
		os.Exit(1)
	}

	if strings.TrimSpace(input) == "" {
		emit("error", "No input provided.")
		emit("done", nil)
		os.Exit(1)
	}

	var req EngineRequest
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		emit("error", fmt.Sprintf("Failed to parse JSON input: %v", err))
		emit("done", nil)
		os.Exit(1)
	}

	engine := scanner.NewEngine()

	// wg tracks the per-channel forwarder goroutines so we can wait for all
	// events to be flushed before emitting "done".
	var wg sync.WaitGroup
	var failed atomic.Bool

	// Log forwarder: runs for both alive and smb commands.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for logMsg := range engine.LogChan {
			if strings.HasPrefix(logMsg, "ERROR:") {
				failed.Store(true)
				emit("error", logMsg)
			} else {
				emit("log", logMsg)
			}
		}
	}()

	switch req.Command {
	case "alive":
		wg.Add(1)
		go func() {
			defer wg.Done()
			for res := range engine.AliveResults {
				if res.IsAlive || res.ARPObserved {
					emit("alive_result", res)
				} else {
					emit("discovery_result", res)
				}
			}
		}()
		engine.StartAliveDiscovery(req.AliveConfig)

	case "smb":
		wg.Add(1)
		go func() {
			defer wg.Done()
			for res := range engine.ScanResults {
				emit("smb_result", res)
			}
		}()
		engine.StartSMBScan(req.ScanConfig)

	default:
		emit("error", "Unknown command: "+req.Command)
		// Close LogChan so the log forwarder goroutine can exit cleanly.
		// No scan was started, so AliveResults/ScanResults/ProgressChan are
		// left open — they hold no senders and are garbage-collected on exit.
		close(engine.LogChan)
		wg.Wait()
		emit("done", nil)
		os.Exit(1)
	}

	// Forward progress events in the main goroutine (sole reader — no race).
	// Completion also waits for all result and log streams below.
	for prog := range engine.ProgressChan {
		emit("progress", prog)
	}

	// Wait for log and result forwarders to drain their channels before emitting done.
	wg.Wait()

	emit("done", nil)
	if failed.Load() {
		os.Exit(1)
	}
}

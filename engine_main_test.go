package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"tknet/scanner"
)

func TestHeadlessChild(t *testing.T) {
	if os.Getenv("TKNET_TEST_CHILD") != "1" {
		return
	}
	os.Args = []string{"tknet-engine", "--headless"}
	main()
	os.Exit(0)
}

func runHeadless(t *testing.T, input []byte, extraEnv ...string) []EngineEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHeadlessChild$")
	cmd.Env = append(os.Environ(), "TKNET_TEST_CHILD=1")
	cmd.Env = append(cmd.Env, extraEnv...)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if e, ok := err.(*exec.ExitError); ok {
			exit = e
		}
		if exit == nil {
			t.Fatal(err)
		}
	}
	var events []EngineEvent
	lines := bufio.NewScanner(bytes.NewReader(output))
	for lines.Scan() {
		var evt EngineEvent
		if err := json.Unmarshal(lines.Bytes(), &evt); err != nil {
			t.Fatalf("invalid event: %q", lines.Text())
		}
		events = append(events, evt)
	}
	if len(events) == 0 || events[len(events)-1].Type != "done" {
		t.Fatalf("missing final done: %s", output)
	}
	for _, event := range events {
		if event.Type == "error" && err == nil {
			t.Fatal("failed request exited successfully")
		}
	}
	return events
}
func TestHeadlessRejectsInvalidRequests(t *testing.T) {
	for _, input := range []string{"{", `{"command":"unknown"}`, `{"command":"alive","alive_config":{"Targets":"192.0.2.1","Threads":-1,"EnableICMP":true}}`, `{"command":"smb","scan_config":{"Targets":"192.0.2.1","Threads":-1}}`} {
		events := runHeadless(t, []byte(input+"\n"))
		errors := 0
		done := 0
		for _, evt := range events {
			if evt.Type == "error" {
				errors++
			}
			if evt.Type == "done" {
				done++
			}
			if evt.Type == "alive_result" {
				t.Fatal("invalid request produced result")
			}
		}
		if errors != 1 || done != 1 {
			t.Fatalf("errors=%d done=%d", errors, done)
		}
	}
}

func TestHeadlessAcceptsEscapedUnicodeScopeWithinUILimit(t *testing.T) {
	// System.Text.Json escapes non-ASCII characters in the desktop request.
	// A valid 1 Mi-character comment must fit the wire limit even at 6 bytes
	// per character. An empty target list keeps this test entirely offline.
	input := []byte(`{"command":"smb","scan_config":{"Targets":"#` + strings.Repeat(`\u96ea`, (1<<20)-1) + `","Threads":1,"Timeout":1}}` + "\n")
	errors := 0
	for _, evt := range runHeadless(t, input) {
		if evt.Type == "error" {
			errors++
			if evt.Data != "ERROR: No valid IPs found to scan via SMB." {
				t.Fatalf("valid UI scope failed at the engine boundary: %v", evt.Data)
			}
		}
	}
	if errors != 1 {
		t.Fatal("request did not reach target validation")
	}
}

func TestHeadlessRejectsOversizedRequestBeforeScanning(t *testing.T) {
	input := []byte(`{"command":"smb","scan_config":{"Targets":"#` + strings.Repeat("x", 8<<20) + `"}}` + "\n")
	events := runHeadless(t, input)
	if len(events) != 2 || events[0].Type != "error" || !strings.Contains(fmt.Sprint(events[0].Data), "Failed to read request") {
		t.Fatalf("oversized input was not rejected at the framing boundary: %+v", events)
	}
}
func TestHeadlessLargeRequestDrainsAllResultsBeforeDone(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses an isolated fake Linux ping command")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nfor target do :; done\nprintf '64 bytes from %s: icmp_seq=1 ttl=64 time=0.123 ms\\n' \"$target\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ping"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	req := EngineRequest{Command: "alive", AliveConfig: scanner.AliveConfig{Targets: "#" + strings.Repeat("x", 70000) + "\n192.0.2.1-120", EnableICMP: true, Threads: 4, Timeout: 1}}
	input, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	events := runHeadless(t, append(input, '\n'), "PATH="+dir)
	results, done := 0, 0
	for _, evt := range events {
		switch evt.Type {
		case "alive_result":
			results++
		case "done":
			done++
		case "error":
			t.Fatalf("%v", evt.Data)
		}
	}
	if results != 120 || done != 1 {
		t.Fatalf("results=%d done=%d", results, done)
	}
}

func TestHeadlessPreservesNoResponseEvidence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("isolated fake ping process")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ping"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	req := EngineRequest{Command: "alive", AliveConfig: scanner.AliveConfig{Targets: "192.0.2.1-3", EnableICMP: true, Attempts: 1, Threads: 2, Timeout: 1}}
	input, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	events := runHeadless(t, append(input, '\n'), "PATH="+dir)
	count := 0
	for _, event := range events {
		if event.Type == "alive_result" {
			t.Fatal("silent address became alive")
		}
		if event.Type == "discovery_result" {
			count++
			data := event.Data.(map[string]interface{})
			if data["IsAlive"] != false || data["Status"] != "No response" || data["Attempts"] != float64(1) || data["CheckedAt"] == "" {
				t.Fatalf("missing result evidence: %v", data)
			}
		}
	}
	if count != 3 {
		t.Fatalf("expected every checked address; got %d", count)
	}
}

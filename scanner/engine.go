package scanner

import (
	"context"
	"fmt"
	"iter"
	"net"
	"slices"
	"strings"
	"sync"
	"tknet/netutil"
)

// Engine manages the execution of scans using a worker pool pattern.
type Engine struct {
	AliveConfig AliveConfig
	ScanConfig  ScanConfig

	// Channels for communication
	AliveResults chan AliveResult
	ScanResults  chan ScanResult
	LogChan      chan string
	ProgressChan chan float64

	// Cancellation context
	ctx      context.Context
	cancel   context.CancelFunc
	cancelMu sync.Mutex
	started  bool // Each engine owns one set of channels and may run only once.
}

// NewEngine creates a new scanning engine.
func NewEngine() *Engine {
	return &Engine{
		AliveResults: make(chan AliveResult, 100),
		ScanResults:  make(chan ScanResult, 100),
		LogChan:      make(chan string, 100),
		ProgressChan: make(chan float64, 10),
	}
}

// Stop cancels any running scans.
func (e *Engine) Stop() {
	e.cancelMu.Lock()
	defer e.cancelMu.Unlock()
	if e.cancel != nil {
		e.cancel()
	}
}

// StartAliveDiscovery parses targets and begins the alive host discovery process.
func (e *Engine) StartAliveDiscovery(cfg AliveConfig) {
	e.cancelMu.Lock()
	if e.started {
		e.cancelMu.Unlock()
		return
	}
	e.started = true
	e.AliveConfig = cfg
	e.ctx, e.cancel = context.WithCancel(context.Background())
	ctx := e.ctx
	e.cancelMu.Unlock()
	go e.runAliveDiscovery(ctx, cfg)
}

func (e *Engine) runAliveDiscovery(ctx context.Context, cfg AliveConfig) {
	e.runAliveDiscoveryWithProbes(ctx, cfg, defaultAliveProbes())
}

func (e *Engine) runAliveDiscoveryWithProbes(ctx context.Context, cfg AliveConfig, probes aliveProbes) {
	// Defers execute in reverse order: result stream closes before completion.
	defer close(e.ProgressChan)
	defer close(e.LogChan)
	defer close(e.AliveResults)
	log := func(message string) {
		select {
		case e.LogChan <- message:
		case <-ctx.Done():
		}
	}
	var err error
	cfg, err = NormalizeAliveConfig(cfg)
	if err != nil {
		log("ERROR: " + err.Error())
		return
	}
	log("Resolving targets...")
	ips, err := netutil.ParseTargets(cfg.Targets)
	if err != nil {
		log(fmt.Sprintf("ERROR: Target parsing failed: %v", err))
		return
	}
	totalIPs := ips.Count()
	if totalIPs == 0 {
		log("ERROR: No valid IPs found to scan.")
		return
	}
	log(fmt.Sprintf("Checking %d IPv4 addresses; ARP-only observations remain unconfirmed.", totalIPs))
	// Limit actual operations, not just hosts: one host can have many TCP probes.
	probeLimit := min(128, max(4, cfg.Threads*2))
	probes.limit = make(chan struct{}, probeLimit)
	log(fmt.Sprintf("Up to %d attempts per unresolved address; at most %d simultaneous probes.", cfg.Attempts, probeLimit))
	jobs := make(chan net.IP)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var completed, confirmed, unconfirmed, incomplete uint64
	warningCounts := make(map[string]int)
	workers := cfg.Threads
	if uint64(workers) > totalIPs {
		workers = int(totalIPs)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if ctx.Err() != nil {
					return
				}
				res := checkAlive(ctx, ip, cfg, probes)
				if ctx.Err() != nil {
					return
				}
				// Emit every completed target so missing responses and errors remain auditable.
				select {
				case e.AliveResults <- res:
				case <-ctx.Done():
					return
				}
				mu.Lock()
				completed++
				if res.IsAlive {
					confirmed++
				} else if res.ARPObserved || len(res.TCPRefusedPorts) > 0 {
					unconfirmed++
				}
				if res.Error != "" || len(res.Warnings) > 0 {
					incomplete++
				}
				if res.Error != "" {
					log(fmt.Sprintf("WARNING: %s: %s", ip, res.Error))
				}
				for _, warning := range res.Warnings {
					method := strings.SplitN(warning, ":", 2)[0]
					warningCounts[method]++
					if warningCounts[method] == 1 {
						log("WARNING: " + warning)
					}
				}
				progress := float64(completed) / float64(totalIPs)
				// Coalesce progress instead of blocking workers behind a slow UI.
				select {
				case e.ProgressChan <- progress:
				default:
					select {
					case <-e.ProgressChan:
					default:
					}
					select {
					case e.ProgressChan <- progress:
					default:
					}
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for ip := range ips.IPs() {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	for _, method := range []string{"ARP", "ICMP", "NetBIOS", "TCP"} {
		if count := warningCounts[method]; count > 0 {
			log(fmt.Sprintf("WARNING: %s reported %d probe error(s); discovery may be incomplete.", method, count))
		}
	}
	log(fmt.Sprintf("Host Discovery completed: %d checked, %d confirmed, %d unconfirmed observations, %d without a confirming response; %d address(es) had probe errors. No response does not mean offline.", completed, confirmed, unconfirmed, completed-confirmed-unconfirmed, incomplete))
}

// StartSMBScan parses targets and begins the SMB authentication and share scanning process.
func (e *Engine) StartSMBScan(cfg ScanConfig) {
	e.cancelMu.Lock()
	defer e.cancelMu.Unlock()
	if e.started {
		return
	}
	e.started = true
	e.ScanConfig = cfg
	e.ctx, e.cancel = context.WithCancel(context.Background())

	go e.runSMBScan(e.ctx, cfg, CheckSMB)
}

func (e *Engine) runSMBScan(ctx context.Context, cfg ScanConfig, check func(context.Context, string, ScanConfig) ScanResult) {
	defer close(e.ScanResults)
	defer close(e.LogChan)
	defer close(e.ProgressChan)
	log := func(message string) {
		select {
		case e.LogChan <- message:
		case <-ctx.Done():
		}
	}
	var err error
	cfg, err = NormalizeScanConfig(cfg)
	if err != nil {
		log("ERROR: " + err.Error())
		return
	}

	log("Resolving targets for SMB Scan...")

	ips, err := netutil.ParseTargets(cfg.Targets)
	if err != nil {
		log(fmt.Sprintf("ERROR: Target parsing failed: %v", err))
		return
	}

	totalIPs := ips.Count()
	if totalIPs == 0 {
		log("ERROR: No valid IPs found to scan via SMB.")
		return
	}

	log(fmt.Sprintf("Total %d IPs will be scanned via SMB.", totalIPs))
	log(fmt.Sprintf("SMB settings: %d concurrent hosts; %ds TCP timeout per attempt; up to %d initial TCP attempts plus one final attempt for unconnected targets (at most %d concurrent); %ds SMB inactivity budget. Configured-account authentication is not retried.", cfg.Threads, cfg.Timeout, smbConnectAttempts, min(cfg.Threads, 8), max(30, cfg.Timeout)))
	if cfg.UseHash {
		log("Authentication: NTLM Hash")
	} else {
		log("Authentication: Password")
	}

	var completed uint64
	var mu sync.Mutex
	var pending []ScanResult
	publish := func(res ScanResult) {
		select {
		case <-ctx.Done():
			return
		case e.ScanResults <- res:
		}
		mu.Lock()
		defer mu.Unlock()
		completed++
		progress := float64(completed) / float64(totalIPs)
		select {
		case e.ProgressChan <- progress:
		default:
			select {
			case <-e.ProgressChan:
			default:
			}
			select {
			case e.ProgressChan <- progress:
			default:
			}
		}
	}
	// Only TCP failures are deferred. No successful connection, authentication
	// failure or partial enumeration may enter the recovery pass. Publish once
	// per IP so counters and reports cannot contain duplicate or stale results.
	runPass := func(targets iter.Seq[ScanResult], count uint64, settings ScanConfig, workers int) {
		jobs := make(chan ScanResult)
		var wg sync.WaitGroup
		for i := uint64(0); i < min(uint64(workers), count); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for previous := range jobs {
					if ctx.Err() != nil {
						return
					}
					res := check(ctx, previous.IP, settings)
					if settings.connectionRecovery {
						res.ConnectionRecoveryAttempted = res.ConnectionAttempts > 0
						res.ConnectionAttempts += previous.ConnectionAttempts
						res.ConnectionErrors = append(previous.ConnectionErrors, res.ConnectionErrors...)
					} else if res.retryConnection && !res.Port445Open && res.EnumerationStatus == "Not attempted" {
						mu.Lock()
						pending = append(pending, res)
						mu.Unlock()
						continue
					}
					publish(res)
				}
			}()
		}
	Dispatch:
		for target := range targets {
			select {
			case <-ctx.Done():
				break Dispatch
			case jobs <- target:
			}
		}
		close(jobs)
		wg.Wait()
	}
	initial := func(yield func(ScanResult) bool) {
		for ip := range ips.IPs() {
			if !yield(ScanResult{IP: ip.String()}) {
				return
			}
		}
	}
	runPass(initial, totalIPs, cfg, cfg.Threads)
	if ctx.Err() == nil && len(pending) > 0 {
		workers := min(cfg.Threads, 8)
		log(fmt.Sprintf("Final TCP verification: %d targets without a connection; %d concurrent hosts; one additional %ds attempt. No previously authenticated host is retried.", len(pending), workers, cfg.Timeout))
		recovery := cfg
		recovery.connectionRecovery = true
		runPass(slices.Values(pending), uint64(len(pending)), recovery, workers)
	}
	if ctx.Err() == nil {
		log("SMB Scan completed.")
	}
}

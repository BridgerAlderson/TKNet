package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tknet/netutil"
)

// Keep transport I/O separate from evidence classification so negative and
// malformed-response cases can be tested without contacting a network.
type aliveProbes struct {
	limit chan struct{} // Shared across a scan to bound simultaneous OS/network operations.
	arp   func(context.Context, net.IP, time.Duration) (bool, string, error)
	ping  func(context.Context, net.IP, uint32) (bool, uint32, error)
	nbns  func(context.Context, net.IP, time.Duration) (string, error)
	tcp   func(context.Context, string, time.Duration) error
	dns   func(context.Context, string) ([]string, error)
}

func defaultAliveProbes() aliveProbes {
	return aliveProbes{
		limit: make(chan struct{}, 16),
		arp:   netutil.ARPPingContext, ping: netutil.PingHostContext,
		nbns: netutil.NBNSQueryContext, dns: net.DefaultResolver.LookupAddr,
		tcp: func(ctx context.Context, target string, timeout time.Duration) error {
			d := net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "tcp4", target)
			if err == nil {
				conn.Close()
			}
			return err
		},
	}
}

// CheckAlive requires a current IP response. DNS records and ARP resolution
// alone are not liveness evidence: both may be stale or supplied by a proxy.
func CheckAlive(ctx context.Context, ip net.IP, cfg AliveConfig) AliveResult {
	return checkAlive(ctx, ip, cfg, defaultAliveProbes())
}

func checkAlive(ctx context.Context, ip net.IP, cfg AliveConfig, probes aliveProbes) AliveResult {
	res := AliveResult{IP: ip.String(), TCPOpenPorts: []int{}, TCPRefusedPorts: []int{}, Warnings: []string{}, ProbeOutcomes: []ProbeOutcome{}, Status: "No response", CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	normalized, err := NormalizeAliveConfig(cfg)
	if err != nil {
		res.Status = "Error"
		res.Error = err.Error()
		return res
	}
	cfg = normalized
	if ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		res.Status = "Error"
		res.Error = "discovery requires a unicast IPv4 target"
		return res
	}
	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		if ctx.Err() != nil {
			res.Status = "Cancelled"
			return res
		}
		if attempt > 1 {
			timer := time.NewTimer(150 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				res.Status = "Cancelled"
				return res
			}
		}
		current := checkAliveAttempt(ctx, ip, cfg, probes, attempt)
		res.Attempts = attempt
		res.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
		res.ProbeOutcomes = append(res.ProbeOutcomes, current.ProbeOutcomes...)
		for _, warning := range current.Warnings {
			if !containsString(res.Warnings, warning) {
				res.Warnings = append(res.Warnings, warning)
			}
		}
		if current.ARPObserved {
			res.ARPObserved = true
			res.MACAddress = current.MACAddress
			res.MACVendor = current.MACVendor
		}
		res.TCPRefusedPorts = appendUniquePorts(res.TCPRefusedPorts, current.TCPRefusedPorts)
		if current.IsAlive {
			res.IsAlive = true
			res.ICMPAlive = current.ICMPAlive
			res.ICMPLatency = current.ICMPLatency
			res.NetBIOSAlive = current.NetBIOSAlive
			res.NetBIOSName = current.NetBIOSName
			res.TCPOpenPorts = current.TCPOpenPorts
			res.DetectionMethod = current.DetectionMethod
			break
		}
		// Retry unanswered probes, not a scan where every IP method failed locally.
		retryable := false
		for _, outcome := range current.ProbeOutcomes {
			if outcome.Method != "ARP" && (outcome.Outcome == "no_response" || outcome.Outcome == "refused") {
				retryable = true
			}
		}
		if !retryable {
			break
		}
	}
	if ctx.Err() != nil {
		res.IsAlive = false
		res.Status = "Cancelled"
		return res
	}
	res.ARPAlive = res.ARPObserved && res.IsAlive
	switch {
	case res.IsAlive:
		res.Status = "Confirmed"
	case res.ARPObserved:
		res.Status = "Unconfirmed (ARP only)"
	case len(res.TCPRefusedPorts) > 0:
		res.Status = "Unconfirmed (TCP refusal)"
	case len(res.Warnings) > 0:
		res.Status = "Incomplete (probe errors)"
	}
	sort.Ints(res.TCPRefusedPorts)
	sort.Strings(res.Warnings)
	if cfg.EnableDNS && (res.IsAlive || res.ARPObserved) {
		timeout := time.Duration(cfg.Timeout) * time.Second
		dnsCtx, cancel := context.WithTimeout(ctx, timeout)
		var names []string
		var err error
		if probes.acquire(dnsCtx) {
			names, err = probes.dns(dnsCtx, ip.String())
			probes.release()
		}
		cancel()
		if err == nil && len(names) > 0 {
			res.DNSName = strings.TrimSuffix(names[0], ".")
		}
	}
	res.Hostname = res.DNSName
	if res.Hostname == "" {
		res.Hostname = res.NetBIOSName
	}
	if ctx.Err() != nil {
		res.IsAlive = false
		res.ARPAlive = false
		res.Status = "Cancelled"
	}
	return res
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func appendUniquePorts(existing, ports []int) []int {
	for _, port := range ports {
		found := false
		for _, old := range existing {
			if port == old {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, port)
		}
	}
	return existing
}

func (p aliveProbes) acquire(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	if p.limit == nil {
		return true
	}
	select {
	case p.limit <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}
func (p aliveProbes) release() {
	if p.limit != nil {
		<-p.limit
	}
}

func checkAliveAttempt(ctx context.Context, ip net.IP, cfg AliveConfig, probes aliveProbes, attempt int) AliveResult {
	res := AliveResult{IP: ip.String(), TCPOpenPorts: []int{}, TCPRefusedPorts: []int{}, Warnings: []string{}, ProbeOutcomes: []ProbeOutcome{}}
	timeout := time.Duration(cfg.Timeout) * time.Second
	var wg sync.WaitGroup
	var mu sync.Mutex
	record := func(method, outcome, detail string, err error) {
		if ctx.Err() != nil {
			outcome = "cancelled"
		}
		mu.Lock()
		defer mu.Unlock()
		if err != nil && ctx.Err() == nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, netutil.ErrNoResponse) && outcome != "no_response" && outcome != "refused" {
			outcome = "error"
			res.Warnings = append(res.Warnings, method+": "+err.Error())
		}
		if err != nil {
			detail = err.Error()
		}
		res.ProbeOutcomes = append(res.ProbeOutcomes, ProbeOutcome{Method: method, Attempt: attempt, Outcome: outcome, Detail: detail})
	}
	if cfg.EnableARP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !probes.acquire(ctx) {
				return
			}
			observed, mac, err := probes.arp(ctx, ip, timeout)
			probes.release()
			if observed && err == nil {
				if normalized, valid := netutil.ValidMAC(mac); valid {
					mac = normalized
				} else {
					err = fmt.Errorf("invalid ARP hardware address")
				}
			}
			outcome := "no_response"
			if observed && err == nil {
				outcome = "observed"
			}
			if err != nil {
				outcome = "error"
			}
			if errors.Is(err, context.DeadlineExceeded) {
				outcome = "no_response"
			}
			record("ARP", outcome, "Address resolution: "+mac+" (not sole liveness evidence)", err)
			if err == nil && observed {
				if mac, ok := netutil.ValidMAC(mac); ok {
					mu.Lock()
					res.ARPObserved = true
					res.MACAddress = mac
					res.MACVendor = netutil.GetMACVendor(mac)
					mu.Unlock()
				}
			}
		}()
	}
	if cfg.EnableNetBIOS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !probes.acquire(ctx) {
				return
			}
			name, err := probes.nbns(ctx, ip, timeout)
			probes.release()
			outcome := "confirmed"
			if err != nil {
				outcome = "error"
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, netutil.ErrNoResponse) {
				outcome = "no_response"
			}
			record("NetBIOS", outcome, name, err)
			if err == nil {
				// A valid node-status response proves liveness even without a workstation name.
				mu.Lock()
				res.NetBIOSAlive = true
				res.NetBIOSName = name
				mu.Unlock()
			}
		}()
	}
	if cfg.EnableICMP && probes.acquire(ctx) {
		alive, rtt, err := probes.ping(ctx, ip, uint32(cfg.Timeout*1000))
		probes.release()
		outcome := "no_response"
		if alive && err == nil {
			outcome = "confirmed"
		}
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			outcome = "error"
		}
		record("ICMP", outcome, "", err)
		if err == nil && alive {
			res.ICMPAlive = true
			res.ICMPLatency = fmt.Sprintf("%dms", rtt)
		}
	}
	// Preserve the existing fallback policy: TCP ports are sampled only if ICMP
	// did not confirm the host. Connection refusals and routing errors are NOT alive.
	if !res.ICMPAlive && cfg.EnableTCP && ctx.Err() == nil {
		for _, port := range cfg.TCPPorts {
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				if !probes.acquire(ctx) {
					return
				}
				err := probes.tcp(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(p)), timeout)
				probes.release()
				outcome := "no_response"
				if err == nil {
					outcome = "confirmed"
				}
				if netutil.IsConnectionRefused(err) {
					outcome = "refused"
				}
				if netutil.IsLocalProbeError(err) {
					outcome = "error"
				}
				record(fmt.Sprintf("TCP:%d", p), outcome, "", err)
				if err == nil {
					mu.Lock()
					res.TCPOpenPorts = append(res.TCPOpenPorts, p)
					mu.Unlock()
				} else if netutil.IsConnectionRefused(err) {
					mu.Lock()
					res.TCPRefusedPorts = append(res.TCPRefusedPorts, p)
					mu.Unlock()
				}
			}(port)
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		res.Status = "Cancelled"
		return res
	}
	sort.Ints(res.TCPOpenPorts)
	sort.Strings(res.Warnings)
	res.IsAlive = res.ICMPAlive || len(res.TCPOpenPorts) > 0 || res.NetBIOSAlive
	res.ARPAlive = res.ARPObserved && res.IsAlive
	if res.IsAlive {
		res.Status = "Confirmed"
	} else if res.ARPObserved {
		res.Status = "Unconfirmed (ARP only)"
	}
	var methods []string
	if res.ICMPAlive {
		methods = append(methods, "ICMP")
	}
	for _, port := range res.TCPOpenPorts {
		methods = append(methods, fmt.Sprintf("TCP:%d", port))
	}
	if res.NetBIOSAlive {
		methods = append(methods, "NetBIOS")
	}
	res.DetectionMethod = strings.Join(methods, ", ")
	sort.Slice(res.ProbeOutcomes, func(i, j int) bool { return res.ProbeOutcomes[i].Method < res.ProbeOutcomes[j].Method })
	return res
}

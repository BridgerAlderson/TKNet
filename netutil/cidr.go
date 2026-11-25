package netutil

import (
	"encoding/binary"
	"fmt"
	"iter"
	"net"
	"sort"
	"strconv"
	"strings"
)

type ipv4Interval struct {
	start, end uint32
}

// Targets stores disjoint IPv4 intervals instead of one allocation per address.
// Count and iteration also support the entire IPv4 space without uint32 overflow.
type Targets struct {
	ranges []ipv4Interval
	count  uint64
}

func (t *Targets) Count() uint64 { return t.count }

// IPs yields unique addresses in numeric order. Each IP has independent storage;
// stopping iteration immediately stops expansion, including for a /0 scope.
func (t *Targets) IPs() iter.Seq[net.IP] {
	return func(yield func(net.IP) bool) {
		for _, span := range t.ranges {
			for value := uint64(span.start); value <= uint64(span.end); value++ {
				ip := make(net.IP, net.IPv4len)
				binary.BigEndian.PutUint32(ip, uint32(value))
				if !yield(ip) {
					return
				}
			}
		}
	}
}

// ParseTargets validates the whole scope before any target can be scanned.
// CIDRs, full/last-octet ranges, individual IPv4 addresses, commas, newlines and
// comment lines are accepted. Overlap is removed without enumerating addresses.
func ParseTargets(input string) (*Targets, error) {
	var ranges []ipv4Interval
	for _, line := range strings.Split(strings.ReplaceAll(input, ",", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		span, err := parseInterval(line)
		if err != nil {
			return nil, fmt.Errorf("invalid scope entry %q: %w", line, err)
		}
		ranges = append(ranges, span)
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	merged := ranges[:0]
	for _, span := range ranges {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if uint64(span.start) <= uint64(last.end)+1 {
				last.end = max(last.end, span.end)
				continue
			}
		}
		merged = append(merged, span)
	}
	result := &Targets{ranges: merged}
	for _, span := range merged {
		result.count += uint64(span.end) - uint64(span.start) + 1
	}
	return result, nil
}

func parseIPv4(value string) (uint32, error) {
	ip := net.ParseIP(value)
	// Reject IPv4-mapped IPv6 too, matching the desktop parser.
	if ip == nil || ip.To4() == nil || strings.Contains(value, ":") {
		return 0, fmt.Errorf("invalid IPv4 address: %q", value)
	}
	return binary.BigEndian.Uint32(ip.To4()), nil
}

func parseInterval(line string) (ipv4Interval, error) {
	if strings.Contains(line, "/") {
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			return ipv4Interval{}, err
		}
		prefix, bits := network.Mask.Size()
		if bits != 32 {
			return ipv4Interval{}, fmt.Errorf("IPv4 CIDR required")
		}
		start := binary.BigEndian.Uint32(network.IP.To4())
		end := start | ^binary.BigEndian.Uint32(network.Mask)
		// Preserve existing usable-host semantics: /31 and /32 include every
		// address; larger networks omit only their own network and broadcast.
		if prefix < 31 {
			start++
			end--
		}
		return ipv4Interval{start, end}, nil
	}
	if strings.Contains(line, "-") {
		parts := strings.Split(line, "-")
		if len(parts) != 2 {
			return ipv4Interval{}, fmt.Errorf("invalid IP range")
		}
		start, err := parseIPv4(strings.TrimSpace(parts[0]))
		if err != nil {
			return ipv4Interval{}, err
		}
		last := strings.TrimSpace(parts[1])
		end, err := parseIPv4(last)
		if err != nil {
			octet, parseErr := strconv.Atoi(last)
			if parseErr != nil || octet < 0 || octet > 255 {
				return ipv4Interval{}, fmt.Errorf("invalid range end: %q", last)
			}
			end = (start & 0xffffff00) | uint32(octet)
		}
		if end < start {
			return ipv4Interval{}, fmt.Errorf("start IP greater than end IP")
		}
		return ipv4Interval{start, end}, nil
	}
	ip, err := parseIPv4(line)
	return ipv4Interval{ip, ip}, err
}

package scanner

import (
	"fmt"
	"sort"
)

// NormalizeAliveConfig applies safe defaults and rejects configurations that
// would silently disable discovery or exhaust local resources.
func NormalizeAliveConfig(cfg AliveConfig) (AliveConfig, error) {
	if cfg.Threads == 0 {
		cfg.Threads = 50
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 3
	}
	if cfg.Attempts == 0 {
		cfg.Attempts = 2
	}
	if cfg.Attempts < 1 || cfg.Attempts > 3 {
		return cfg, fmt.Errorf("discovery attempts must be between 1 and 3")
	}
	if cfg.Threads < 1 || cfg.Threads > 256 {
		return cfg, fmt.Errorf("threads must be between 1 and 256")
	}
	if cfg.Timeout < 1 || cfg.Timeout > 60 {
		return cfg, fmt.Errorf("timeout must be between 1 and 60 seconds")
	}
	if !cfg.EnableICMP && !cfg.EnableTCP && !cfg.EnableNetBIOS {
		return cfg, fmt.Errorf("enable ICMP, TCP or NetBIOS; DNS and ARP alone cannot confirm host liveness")
	}
	if cfg.EnableTCP {
		if len(cfg.TCPPorts) == 0 {
			return cfg, fmt.Errorf("TCP discovery requires at least one port")
		}
		ports := make(map[int]bool)
		for _, port := range cfg.TCPPorts {
			if port < 1 || port > 65535 {
				return cfg, fmt.Errorf("invalid TCP port: %d", port)
			}
			ports[port] = true
		}
		if len(ports) > 32 {
			return cfg, fmt.Errorf("at most 32 TCP discovery ports are supported")
		}
		cfg.TCPPorts = make([]int, 0, len(ports))
		for port := range ports {
			cfg.TCPPorts = append(cfg.TCPPorts, port)
		}
		sort.Ints(cfg.TCPPorts)
	}
	return cfg, nil
}

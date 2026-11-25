package scanner

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// NormalizeScanConfig validates local resource limits before any network I/O.
func NormalizeScanConfig(cfg ScanConfig) (ScanConfig, error) {
	if cfg.Threads == 0 {
		cfg.Threads = 50
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 3
	}
	if cfg.Threads < 1 || cfg.Threads > 256 {
		return cfg, fmt.Errorf("threads must be between 1 and 256")
	}
	if cfg.Timeout < 1 || cfg.Timeout > 60 {
		return cfg, fmt.Errorf("timeout must be between 1 and 60 seconds")
	}
	if cfg.UseHash && !cfg.PortScanOnly {
		if strings.TrimSpace(cfg.Username) == "" {
			return cfg, fmt.Errorf("NTLM hash authentication requires a username")
		}
		value, err := hex.DecodeString(strings.TrimSpace(cfg.Password))
		if err != nil || len(value) != 16 {
			return cfg, fmt.Errorf("invalid NTLM hash format (must be 32 hex characters)")
		}
	}
	return cfg, nil
}

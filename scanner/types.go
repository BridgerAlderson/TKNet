package scanner

// AliveConfig holds configuration for alive host discovery.
type AliveConfig struct {
	Targets       string // CIDR notation or newline-separated IP list
	Threads       int    // Maximum concurrent goroutines
	Timeout       int    // Connection timeout in seconds
	Attempts      int    // 1–3 attempts for unresolved hosts; default 2
	EnableICMP    bool   // Enable ICMP ping probe
	EnableTCP     bool   // Enable TCP multi-port probe
	EnableNetBIOS bool   // Enable NetBIOS UDP 137 query
	EnableDNS     bool   // Enable DNS reverse lookup
	EnableARP     bool   // Enable ARP discovery
	TCPPorts      []int  // TCP ports to probe for alive detection
}

// AliveResult holds the discovery result for a single IP.
type AliveResult struct {
	IP              string
	Hostname        string // Best hostname found (reverse DNS or NetBIOS)
	IsAlive         bool
	Status          string   // Confirmed, Unconfirmed (ARP only), No response, Cancelled, Error
	ARPObserved     bool     // Address resolution is NOT proof of host liveness (cache/proxy ARP)
	Warnings        []string // Probe failures, distinct from normal timeouts
	Attempts        int
	CheckedAt       string // UTC RFC3339Nano; time of final observation
	ProbeOutcomes   []ProbeOutcome
	TCPRefusedPorts []int // Unconfirmed response; never counted as an open port
	MACAddress      string
	MACVendor       string
	ICMPAlive       bool
	ICMPLatency     string // e.g. "2ms", empty if not alive
	TCPOpenPorts    []int  // TCP ports found open
	NetBIOSAlive    bool
	NetBIOSName     string // Machine name from NBNS response
	DNSName         string // FQDN from PTR record
	ARPAlive        bool
	DetectionMethod string // e.g. "ICMP, TCP:445, NetBIOS"
	Error           string
}

// ProbeOutcome records what was actually attempted, including negative results.
type ProbeOutcome struct {
	Method  string
	Attempt int
	Outcome string // confirmed, observed, refused, no_response, error, cancelled
	Detail  string
}

// ScanConfig holds configuration for the SMB share scan.
type ScanConfig struct {
	Targets          string // CIDR notation or newline-separated IP list
	Username         string
	Password         string // Plaintext password or NTLM hash
	Domain           string
	UseHash          bool // true = Password field contains NTLM hash
	Threads          int
	Timeout          int  // Connection timeout in seconds
	PortScanOnly     bool // true = only check port 445, skip SMB auth
	ResolveHostnames bool // Optional reverse lookup after SMB has finished.

	// Feature Enhancements: OS & Device Analysis
	EnableWMI          bool   // Enable WMI queries for detailed OS info
	EnableSNMP         bool   // Enable SNMP queries for network devices
	SNMPCommunity      string // SNMP v2c community string (e.g. "public")
	connectionRecovery bool   // Internal final sweep: one TCP attempt; never set from JSON.
}

// ShareInfo holds information about a single SMB share.
type ShareInfo struct {
	Name        string
	ShareType   uint32 // SRVSVC shi1_type, including special/temporary/cluster flags.
	CanRead     bool
	CanWrite    bool
	ReadCheck   string `json:",omitempty"` // Disk shares: Granted, Denied, Inconclusive, or Not checked.
	WriteCheck  string `json:",omitempty"`
	AccessError string // Non-permission failures or checks not completed; never a denial claim.
}

// MS-SRVS: the low byte identifies the resource; upper bits are flags.
// Hidden administrative and clustered disk shares still support file access.
func (s ShareInfo) FileAccessApplicable() bool { return s.ShareType&0xff == 0 }

// ScanResult holds the SMB scan result for a single IP.
type ScanResult struct {
	IP                          string
	Hostname                    string
	Port445Open                 bool
	ConnectionAttempts          int      // Initial TCP attempts, before any SMB authentication.
	ConnectionErrors            []string // Initial connection failure categories, including recovered failures.
	ConnectionRecoveryAttempted bool     // One final TCP attempt after the initial sweep, at lower concurrency.
	SMBVersion                  string   // "SMBv2", "SMBv3", "SMBv1 Only (Unsupported)", ""
	CredentialSource            string   `json:",omitempty"` // Submitted credentials, independent of server-side account mapping.
	OSVersion                   string   // Target OS Version
	IsAdmin                     bool     // True if connected as Local Administrator (can access ADMIN$ or C$)
	Shares                      []ShareInfo
	EnumerationStatus           string   // Not attempted, Complete, Partial, Failed
	Warnings                    []string // Metadata or temporary-file cleanup failures; never credentials
	WMIInfo                     string   // Detailed OS version from WMI (e.g. "Microsoft Windows 10 Pro|10.0.19041")
	SNMPInfo                    string   // System Description from SNMP (sysDescr)
	Error                       string
	Status                      string // "Queued", "Scanning", "Done", "Error"
	retryConnection             bool   // Set only by a failed initial TCP dial, before any authentication.
}

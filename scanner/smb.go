package scanner

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"tknet/netutil"

	"github.com/cloudsoda/go-smb2"
)

// CheckSMB connects to port 445, authenticates, lists shares, and tests permissions.
func CheckSMB(ctx context.Context, ip string, cfg ScanConfig) ScanResult {
	result := checkSMB(ctx, ip, cfg, systemSMBBackend{})
	result.Hostname = smbHostname(ctx, cfg, result, net.DefaultResolver.LookupAddr)
	return result
}

// The SMB session has already closed. A missing name cannot change its result.
func smbHostname(ctx context.Context, cfg ScanConfig, result ScanResult, lookup func(context.Context, string) ([]string, error)) string {
	if !cfg.ResolveHostnames || cfg.PortScanOnly || !result.Port445Open || ctx.Err() != nil {
		return ""
	}
	nameCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	names, err := lookup(nameCtx, result.IP)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ""
}

func checkSMB(ctx context.Context, ip string, cfg ScanConfig, backend smbBackend) ScanResult {
	res := ScanResult{
		IP:                ip,
		Status:            "Error",
		Shares:            make([]ShareInfo, 0),
		Warnings:          make([]string, 0),
		EnumerationStatus: "Not attempted",
	}
	var err error
	cfg, err = NormalizeScanConfig(cfg)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if err := ctx.Err(); err != nil {
		res.Status = "Cancelled"
		res.Error = err.Error()
		return res
	}

	timeout := time.Duration(cfg.Timeout) * time.Second
	// The UI setting is a TCP connect timeout. Authentication (including a DC)
	// and share operations need a separate, less aggressive inactivity budget.
	protocolTimeout := max(30*time.Second, timeout)

	// 1. Check if Port 445 is open
	target := fmt.Sprintf("%s:445", ip)
	attempts := smbConnectAttempts
	if cfg.connectionRecovery {
		attempts = 1
	}
	conn, failures, err := connectSMB(ctx, target, timeout, attempts, backend.dial, waitSMBConnect)
	res.ConnectionErrors = failures
	res.ConnectionAttempts = len(failures)
	if err != nil {
		res.retryConnection = ctx.Err() == nil && retrySMBConnect(err)
		res.Error = fmt.Sprintf("Port 445 check failed: %v", err)
		if ctx.Err() != nil {
			res.Status = "Cancelled"
		}
		return res
	}
	res.ConnectionAttempts++
	conn = guardSMBConnection(ctx, conn, protocolTimeout)
	res.Port445Open = true

	if cfg.PortScanOnly {
		conn.Close()
		res.Status = "Done"
		return res
	}

	// 2. Setup SMB Dialer with Credentials.
	// Each auth attempt opens its own TCP connection. We track finalConn separately
	// so that the original conn is always explicitly closed, preventing leaks when
	// a later guest attempt succeeds and takes ownership of a new connection.
	var session smbSession
	var finalConn net.Conn
	var authMethod string
	var credentialError error
	var guestError error

	// Attempt 1: Provided Credentials
	if cfg.Username != "" {
		initiator := &smb2.NTLMInitiator{
			User:   cfg.Username,
			Domain: cfg.Domain,
		}

		if cfg.UseHash {
			hashBytes, err := hex.DecodeString(strings.TrimSpace(cfg.Password))
			if err == nil && len(hashBytes) == 16 {
				initiator.Hash = hashBytes
			} else {
				conn.Close()
				res.Error = "Invalid NTLM Hash format (must be 32 hex characters)"
				return res
			}
		} else {
			initiator.Password = cfg.Password
		}

		if s, dialErr := smbOperation(conn, func() (smbSession, error) {
			return backend.authenticate(ctx, conn, ip, initiator)
		}); dialErr == nil {
			session = s
			finalConn = conn
			authMethod = "Authenticated"
			res.CredentialSource = "Configured"
		} else {
			credentialError = dialErr
			conn.Close() // auth failed; close this connection before next attempt
		}
	} else {
		conn.Close() // no credentials provided; release the port-check connection
	}

	// Attempt 2: Guest Session (User: Guest, No Password)
	if session == nil && ctx.Err() == nil {
		connGuest, errGuest := backend.dial(ctx, target, timeout)
		guestError = errGuest
		if errGuest == nil {
			connGuest = guardSMBConnection(ctx, connGuest, protocolTimeout)
			initiator := &smb2.NTLMInitiator{User: "Guest", Password: ""}
			if s, dialErr := smbOperation(connGuest, func() (smbSession, error) {
				return backend.authenticate(ctx, connGuest, ip, initiator)
			}); dialErr == nil {
				session = s
				finalConn = connGuest
				authMethod = "Guest Session"
				res.CredentialSource = "Guest"
			} else {
				guestError = dialErr
				connGuest.Close()
			}
		}
	}

	if session == nil {
		if ctx.Err() != nil {
			res.Status = "Cancelled"
			res.Error = ctx.Err().Error()
		} else {
			res.Error = "SMB authentication failed: " + smbAuthFailure(guestError)
			if credentialError != nil {
				res.Error = "Configured-account authentication failed: " + smbAuthFailure(credentialError) + "; Guest: " + smbAuthFailure(guestError)
			}
		}
		return res
	}
	if credentialError != nil {
		res.Warnings = append(res.Warnings, "Configured-account authentication failed ("+smbAuthFailure(credentialError)+"); using Guest. The share list and permissions may be more limited.")
	}

	session = session.WithContext(ctx)
	defer finalConn.Close()
	defer func() {
		// Results are already known. A missing/invalid logout response must
		// not spend another full authentication budget before delivering them.
		cleanupCtx, cancel := context.WithTimeout(ctx, min(3*time.Second, timeout))
		defer cancel()
		_ = smbOperationError(finalConn, session.WithContext(cleanupCtx).Logoff)
	}()

	// Status shows the provided-credential or guest path used.
	res.Status = authMethod

	// go-smb2 negotiates the highest supported dialect (SMBv2 or SMBv3).
	// The library doesn't expose the exact negotiated dialect in its high-level API,
	// but a successful connection guarantees at least SMBv2.
	res.SMBVersion = "SMBv2/v3"

	// Enumerate before optional probes, and retain every known name before testing
	// access. A later timeout/cancellation must never erase already listed shares.
	listed, listErr := smbOperation(finalConn, session.ListShares)
	res.EnumerationStatus = "Complete"
	seen := make(map[string]bool)
	for _, entry := range listed {
		key := strings.ToUpper(entry.Name)
		if key == "IPC$" || seen[key] {
			continue
		}
		seen[key] = true
		share := ShareInfo{Name: entry.Name, ShareType: entry.Type}
		if share.FileAccessApplicable() {
			share.ReadCheck, share.WriteCheck = "Not checked", "Not checked"
			share.AccessError = "Access check not completed"
		}
		res.Shares = append(res.Shares, share)
	}
	if listErr != nil {
		res.EnumerationStatus = "Failed"
		if len(listed) > 0 {
			res.EnumerationStatus = "Partial"
		}
		res.Error = fmt.Sprintf("Failed to list shares completely: %v", listErr)
	}
	if err := ctx.Err(); err != nil {
		res.Status = "Cancelled"
		res.Error = err.Error()
		return res
	}
	if listErr != nil && len(res.Shares) == 0 {
		return res
	}

	// Observe administrative-share access. A mount alone is not proof of
	// local administrator membership on every Windows/Samba configuration.
	adminFs, adminErr := smbOperation(finalConn, func() (smbShare, error) { return session.Mount("ADMIN$") })
	if adminErr == nil {
		res.IsAdmin = true
		_ = smbOperationError(finalConn, adminFs.WithContext(ctx).Umount)
	} else {
		// Fallback check: C$
		cFs, cErr := smbOperation(finalConn, func() (smbShare, error) { return session.Mount("C$") })
		if cErr == nil {
			res.IsAdmin = true
			_ = smbOperationError(finalConn, cFs.WithContext(ctx).Umount)
		}
	}

	// 4. Attempt OS Version / Dialect Fingerprinting via IPC$ (Best Effort)
	// We mount IPC$ to check its availability and sometimes glean info,
	// though go-smb2 abstracts away the TreeConnect response.
	ipcFs, ipcErr := smbOperation(finalConn, func() (smbShare, error) { return session.Mount("IPC$") })
	if ipcErr == nil {
		// Just mounting IPC$ successfully proves we have a valid session.
		// Native OS is often leaked during NTLM SSP, but go-smb2 hides this in the library.
		// Record IPC$ access without guessing the operating system.
		res.OSVersion = "SMB server (IPC$ accessible)"
		_ = smbOperationError(finalConn, ipcFs.WithContext(ctx).Umount)
	} else {
		res.OSVersion = "Unknown"
	}

	// Test permissions in the same authenticated session, without re-authentication.
	for i := range res.Shares {
		if err := ctx.Err(); err != nil {
			res.Status = "Cancelled"
			res.Error = err.Error()
			return res
		}
		share := &res.Shares[i]
		if !share.FileAccessApplicable() {
			continue
		}
		name := share.Name
		share.AccessError = ""

		// Try to mount the share
		fs, err := smbOperation(finalConn, func() (smbShare, error) { return session.Mount(name) })
		if err != nil {
			if smbPermissionDenied(err) {
				share.ReadCheck, share.WriteCheck = "Denied", "Denied"
			} else {
				share.AccessError = fmt.Sprintf("Mount check failed: %v", err)
			}
			continue
		}
		fs = fs.WithContext(ctx)

		// Test Read Access (List root directory)
		_, err = smbOperation(finalConn, func() ([]os.FileInfo, error) { return fs.ReadDir(".") })
		share.ReadCheck = smbAccessOutcome(err)
		share.CanRead = err == nil
		if share.ReadCheck == "Denied" {
			share.AccessError = "Root listing denied. Write access was not checked."
		} else if err != nil {
			share.AccessError = fmt.Sprintf("Read check failed: %v. Write access was not checked.", err)
		}

		// Test Write Access (Create and delete a temporary file)
		if share.CanRead {
			testFileName := fmt.Sprintf("tknet_test_%d.tmp", time.Now().UnixNano())
			var warnings []string
			share.CanWrite, err = smbOperation(finalConn, func() (bool, error) {
				var writable bool
				var openErr error
				writable, warnings, openErr = checkShareWriteDetailed(testFileName, func(path string, flags int, mode os.FileMode) (io.Closer, error) {
					return fs.OpenFile(path, flags, mode)
				}, fs.Remove)
				return writable, openErr
			})
			share.WriteCheck = smbAccessOutcome(err)
			if share.WriteCheck == "Inconclusive" {
				share.AccessError = fmt.Sprintf("Write check failed: %v", err)
			}
			for _, warning := range warnings {
				res.Warnings = append(res.Warnings, name+": "+warning)
			}
		}

		if err := smbOperationError(finalConn, fs.Umount); err != nil {
			res.Warnings = append(res.Warnings, name+": share disconnect failed")
		}
	}

	if err := ctx.Err(); err != nil {
		res.Status = "Cancelled"
		res.Error = err.Error()
		return res
	}

	// 7. WMI OS Info Gathering (Feature Enhancement)
	if cfg.EnableWMI && cfg.UseHash {
		res.Warnings = append(res.Warnings, "WMI skipped: this API requires a password or an existing Windows session, not an NTLM hash")
	} else if cfg.EnableWMI && credentialError != nil {
		// Guest may enumerate successfully after the configured logon fails.
		// Do not submit that rejected identity again through another protocol.
		res.Warnings = append(res.Warnings, "WMI skipped: configured-account authentication failed; rejected credentials were not reused")
	} else if cfg.EnableWMI && ctx.Err() == nil {
		wmiInfo, err := netutil.GetWMIOSInfo(ip, cfg.Username, cfg.Password, cfg.Domain)
		if err == nil {
			res.WMIInfo = wmiInfo
			res.OSVersion = wmiInfo // Override generic OS version with accurate WMI info
		} else {
			res.Warnings = append(res.Warnings, "WMI metadata unavailable")
		}
	}

	// 8. SNMP Info Gathering (Feature Enhancement)
	if cfg.EnableSNMP && ctx.Err() == nil {
		snmpInfo, err := netutil.GetSNMPInfoContext(ctx, ip, cfg.SNMPCommunity, cfg.Timeout)
		if err == nil {
			res.SNMPInfo = snmpInfo
			if res.OSVersion == "Unknown" || res.OSVersion == "" {
				res.OSVersion = "SNMP Device"
			}
		} else {
			res.Warnings = append(res.Warnings, "SNMP metadata unavailable")
		}
	}

	return res
}

func smbAccessOutcome(err error) string {
	if err == nil {
		return "Granted"
	}
	if smbPermissionDenied(err) {
		return "Denied"
	}
	return "Inconclusive"
}

func smbPermissionDenied(err error) bool {
	var response *smb2.ResponseError
	return errors.Is(err, os.ErrPermission) || (errors.As(err, &response) && response.Code == 0xc0000022)
}

// Authentication diagnostics never include server-supplied text, passwords or
// hashes. Keep the distinction between a rejected login and a transport failure.
func smbAuthFailure(err error) string {
	var transport *smb2.TransportError
	if errors.As(err, &transport) {
		return smbAuthFailure(transport.Err)
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "SMB response timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "SMB response timed out"
	}
	var response *smb2.ResponseError
	if errors.As(err, &response) {
		detail := ""
		// MS-ERREF names describe the server's reply, not a local guess
		// that a password is wrong or the remote host is offline.
		switch response.Code {
		case 0xc0000192:
			detail = " (STATUS_NETLOGON_NOT_STARTED: server reports that Netlogon is not started)"
		case 0xc000005e:
			detail = " (STATUS_NO_LOGON_SERVERS: server reports no available domain logon server)"
		case 0xc000006d:
			detail = " (STATUS_LOGON_FAILURE: server rejected the logon)"
		}
		return fmt.Sprintf("server returned NTSTATUS 0x%08x%s", response.Code, detail)
	}
	return "connection or authentication negotiation failed"
}

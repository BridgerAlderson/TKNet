# Changelog

## Unreleased

### Interface

- Show only confirmed live hosts in the default discovery view. Keep unanswered,
  unconfirmed and failed probes available through the explicit all-addresses view.
- Export completed discovery targets as IP-only TXT or JSON from the Export menu;
  sort numerically, remove duplicates and preserve the selected scan while saving.
  TXT is UTF-8 without a BOM, with one address per line for Nmap input lists.
- Desktop workspace with a collapsible scope panel, scrollable settings,
  share access chips, empty states and activity log.
- Sonar application icon in the header, desktop window and Windows executable.
- Numeric IPv4 sorting, complete-address column widths, metadata filtering and
  one collection reset per filtered view instead of one update per result.
- Visible/checked discovery counts, Ctrl+F and Escape shortcuts, keyboard-accessible
  share chips, and bounded long share labels with a persistent access indicator.

### Reliability and packaging

- Handle simultaneous starts against the same engine cache on Windows. A second
  publisher verifies and reuses the installed engine. A damaged cache entry can
  still be repaired.
- Build the desktop and tests with .NET 10 LTS and require Go 1.27.4 or later.
- Verify the Dolphin process and address its unique desktop-bus connection before delivering an SMB URL.
- Record distinct read and write check outcomes. A denied root listing leaves write access untested.
- Identify the credential source in SMB reports and support optional hostname lookup after the session has closed.
- Omit application debug symbols from release packages and restrict the development engine fallback to the application directory.

- Preserve the selected scan in CSV/discovery JSON exports and the selected scope
  in text saves even when UI data changes while the save dialog is open.
- Skip optional WMI authentication after the configured SMB account was rejected;
  retain successful Guest enumeration without resubmitting the rejected identity.
- Accept the desktop's full scope character limit when Unicode is JSON-escaped;
  keep a bounded 8 MiB engine request frame.
- Reject SNMP error-status packets instead of treating their variable bindings
  as successful device metadata.
- Stream merged IPv4 intervals without a 65,536-target cap; retain numeric order,
  deduplication, cancellation and the final SMB TCP recovery pass for large scopes.
- Recover transient initial TCP failures with up to three spaced connection
  attempts, without retrying configured-account authentication or adding host
  discovery before SMB. Record attempts and recovered connection failures.
- Show per-share failures in Diagnostics and Activity; separate incomplete
  enumeration from incomplete permission checks. Export all SMB results,
  including unreachable hosts, to a credential-free JSON evidence report.
- Explain server-reported Netlogon, domain-logon-server and logon-rejection
  NTSTATUS codes without guessing that all failures are incorrect passwords.
- Test 995 targets at 50 workers/10 seconds across three varying TCP-failure
  schedules; cover bounded recovery, cancellation and one login per host.
- Preserve SMB sessions while idle; separate TCP connect and SMB inactivity
  budgets so slow authentication does not silently reduce results via Guest.
- Enumerate every SRVSVC continuation page in the existing authenticated session;
  validate RPC fragments/status and retain known shares if later pages fail.
- Probe directory readability without fetching the entire root. Distinguish
  failed access checks from permission denials in share chips, summaries and CSV.
- Disclose configured-account failures before Guest fallback; preserve one
  configured-account authentication attempt per host and existing Dolphin handoff.
- Add protocol, cancellation, deadline and isolated SMB2/NTLM regression fixtures.
- Regression coverage for provided-account authentication, share permission denial,
  credential-preserving Dolphin handoff, cancellation and engine protocol failures.
- Isolated engine builds, validated publish output, shared build locks and rollback
  protection for existing release packages.
- MIT license, bundled third-party notices, contributor guidance, issue templates,
  Dependabot configuration and Linux/Windows quality workflows.

See [release verification](docs/RELEASE_READINESS.md) for tested platforms and package checksums.

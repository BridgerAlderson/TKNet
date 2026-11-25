# Reading host discovery results

The **Discovery** tab opens with the list of IPv4 addresses that answered during the scan. Each confirmed address has at least one successful IP-level check. A warning from another probe can appear on the same row.

Under **Settings**, open **Host discovery** and select **Show all checked IP addresses** to see what happened to the rest of the scope. The full JSON report includes those rows regardless of the current view.

| Status | What TKNet observed |
| --- | --- |
| `Confirmed` | An ICMP echo reply from the target, a successful TCP connection, or a validated NetBIOS node status response. |
| `Unconfirmed (ARP only)` | An IPv4-to-MAC mapping without a confirming IP response. |
| `Unconfirmed (TCP refusal)` | A TCP connection was refused and the other checks did not confirm the address. |
| `No response` | The enabled probes received no confirming reply. The device may be offline, filtered, or temporarily unreachable. |
| `Incomplete (probe errors)` or `Error` | A probe, tool, or configuration error affected the check. The diagnostics and report give the reason. |

A confirmed address describes a response at the recorded time. Gateways and proxies can answer for other devices. Reverse DNS names and vendor names provide context, and ARP mappings can outlive the device that supplied them. Only confirmed addresses have `IsAlive=true`.

## Exporting results

After a discovery scan finishes successfully, choose **Alive IPs (TXT)** or **Alive IPs (JSON)** from the **Export** menu. Both formats remove duplicates and sort addresses numerically. The export uses the selected scan even if the table is filtered, a different tab is open, or a new scan starts while the save dialog is open.

| Format | Contents |
| --- | --- |
| TXT | One IPv4 address per line in UTF-8, without a header or byte order mark. An empty list produces an empty file. |
| JSON | An array of IPv4 strings, such as `["192.0.2.9", "192.0.2.10"]`. An empty list produces `[]`. |

The text file is compatible with Nmap's `-iL` input format. [Nmap target list format](https://nmap.org/book/man-target-specification.html)

For interrupted scans and troubleshooting, use **Export discovery report (JSON)** under **Settings**. The report records completion state, observation times, attempt counts, and outcomes from individual probes. [Comparing results against a known inventory](DISCOVERY_ACCEPTANCE.md)

## Probes and network interfaces

**Maximum attempts** defaults to two and accepts values from one to three. TKNet retries unresolved addresses. A successful ICMP reply skips the TCP fallback for that address, so an empty **Open TCP Ports** cell can also mean the TCP check did not run.

On Linux, ICMP uses `ping`. ARP uses the local interface selected by the kernel route and requires `iproute2`, a supported `arping`, and the appropriate OS permissions. TKNet skips ARP for routed destinations and tunnels without broadcast support. It records missing tools and permission errors while other enabled methods continue. On Windows, the operating system can supply cached address information. [Windows SendARP](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp)

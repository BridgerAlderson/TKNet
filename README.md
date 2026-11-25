# TKNet

TKNet is a desktop scanner for SMB access reviews and IPv4 host discovery on Linux and Windows. Security teams can use it to inventory file shares, check what a particular account can access, and export the hosts that responded during a network assessment.

![TKNet showing read and write access across four example SMB servers](docs/quality/ui-preview/02-smb-1400x900.png)

## Inspect SMB shares

Enter an IPv4 scope, set the account under **Settings > SMB authentication**, and select **Scan SMB**. TKNet connects directly to TCP 445, so it can inspect a file server that blocks ping. The report shows which sessions used the supplied credentials and flags a fallback to Guest. A port-only check is also available for inventory work that requires no login.

TKNet follows the server's share list across multiple response pages. A share stays in the inventory when its root denies access. If enumeration stops midway, the report keeps the names already received and marks that server's list as partial. In the project's loopback SMB2 test, the scanner found all 134 expected resources across four pages. When the test server refused the second page, it retained the 39 known resources. [SMB verification results](docs/RELEASE_READINESS.md)

For disk shares, TKNet attempts to list the root. If that succeeds, it checks write access by creating and removing a new temporary file. The report records read and write outcomes separately and flags cleanup failures. Printer queues appear with their resource type. A driver share such as `print$` can be inspected when the server exposes it as a disk share. [Reading an SMB report](docs/SMB_REPORT_REVIEW.md)

Double-click a disk share to open it. On Linux, TKNet can pass the configured domain account and password to Dolphin over the desktop session bus. On Windows, Explorer uses the current Windows session. [Opening shares in Dolphin](docs/SMB_DOLPHIN.md)

## Discover live hosts

**Host discovery** accepts individual IPv4 addresses, ranges and CIDR blocks in the same scope. TKNet merges overlapping entries before scanning. An address enters the confirmed list after an ICMP echo reply, a successful TCP connection or a validated NetBIOS response. The full report also records ARP observations, refused connections, unanswered probes and errors.

After a completed scan, use **Export > Alive IPs (TXT)** for one confirmed address per line or **Alive IPs (JSON)** for a JSON array. Both formats use numeric IP order. Use CSV to share a result table, or export the full discovery or SMB report from **Settings** to keep per-host evidence and errors. [Discovery results and exports](docs/HOST_DISCOVERY.md)

## Build and run

Run the commands below from the repository root with Go 1.27.4 or later and the .NET 10 SDK. The scripts build the Go engine and embed it in the Avalonia desktop application. [Supported SDK versions](global.json)

**Linux x64**

```sh
./build.sh
./release-linux/TKNetUI
```

**Windows x64 (PowerShell)**

```powershell
.\build.bat
.\release\TKNetUI.exe
```

To distribute a build, copy the entire output directory with its native libraries. The package includes the .NET runtime. Linux discovery uses `ping` for ICMP and `iproute2` and `arping` for local ARP checks. Opening shares with the configured account on Linux requires Dolphin and KIO SMB support.

## Project information

Build and test instructions for contributors are in the [contributing guide](CONTRIBUTING.md). TKNet is distributed under the [MIT license](LICENSE). Dependency licenses are listed in the [third-party notices](THIRD_PARTY_NOTICES.txt).

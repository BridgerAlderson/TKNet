# Evaluating host discovery

Use a known inventory to measure which devices a discovery scan finds and which addresses it incorrectly marks as live. The comparison tool reads saved reports offline. A reference inventory should record device state independently, for example from a console or a management system.

## Compare a scan with an inventory

1. Record the addresses, their known state, the time of observation, and the network connection used. Keep the scope and device state consistent across tools. Repeat the measurements if conditions change.
2. Complete a TKNet discovery scan. Under **Settings**, choose **Export discovery report (JSON)**. This report includes checks that received no response.
3. Save the reference inventory as `reports/truth.json`. This example uses documentation addresses.

```json
{
  "Source": "Lab console",
  "ObservedAt": "2026-10-08T12:00:00Z",
  "Scenario": "Wired management network",
  "Hosts": [
    {"IP": "192.0.2.10", "Alive": true},
    {"IP": "192.0.2.11", "Alive": false}
  ]
}
```

Save TKNet's discovery report as `reports/tknet-report.json` and run the comparison from the repository root.

```sh
python3 tools/discovery_compare.py \
  --truth reports/truth.json \
  --report TKNet=reports/tknet-report.json \
  --output reports/comparison.json
```

To compare a second tool, add another `--report Label=file.json`. For a tool with a different export format, map its fields to `Completed: true` and a `Results` array with a string `IP` and a boolean `IsAlive` for each checked address.

For a saved Nmap XML report, supply the exact input scope from that run as an array of IPv4 strings. Nmap can omit silent addresses from its XML host records. The comparison tool checks the XML completion status, total host count, and consistency of the listed hosts before scoring. [Nmap XML format](https://nmap.org/book/output-formats-xml-output.html)

```sh
python3 tools/discovery_compare.py \
  --truth reports/truth.json \
  --report TKNet=reports/tknet-report.json \
  --nmap reports/recorded-nmap.xml \
  --nmap-scope reports/recorded-nmap-scope.json \
  --output reports/nmap-comparison.json
```

## Interpret the scores

`FalsePositiveIPs` lists known offline addresses reported as live. `FalseNegativeIPs` lists known live addresses that did not receive confirmation. Precision is the fraction of predicted live addresses that were actually live. Recall is the fraction of known live addresses that the tool found.

Scores use only addresses with an independent label. Other scanned addresses appear under `UnlabelledIPs`. A metric with an empty denominator is `null`. An incomplete scan, duplicate entries, or a reference address missing from the scan causes a validation error.

## Regression coverage

| Scenario | Expected behavior |
| --- | --- |
| Lost ICMP or NetBIOS reply, or an initial TCP timeout | A valid reply on the second attempt confirms the address. |
| Repeated ARP mapping or TCP refusal | The record stays unconfirmed. A refused connection contributes no open port. |
| Local tool fails, or the user stops discovery during a retry delay | The record includes the error, or cancellation ends the pending retry. |
| Multiple hosts and ports share a probe limit | Concurrency stays within the limit and each outstanding check finishes. |
| Ethernet and Wi-Fi share a subnet, or the route changes to a VPN | Local ARP follows the selected interface. Routed targets, unsuitable links, and network or broadcast addresses are excluded from the local ARP check. |
| All targets are silent | The engine sends every checked record before completion. The UI retains incomplete and unanswered results. |
| Linux loopback | A local ICMP reply or a successful connection to a temporary listener confirms the address. ARP is skipped on loopback. |

```sh
go test -race -count=1 ./...
go vet ./...
dotnet run --project tests/TKNetUI.Tests/TKNetUI.Tests.csproj
python3 -m unittest discover -s tests/discovery -v
```

The retry and routing fixtures use controlled responses and synthetic interfaces. On a physical network, filtering can keep a live device silent for every attempt and a proxy can reply on a device's behalf. Evaluate each Ethernet, Wi-Fi, or VPN path against the inventory observed on that path.

#!/usr/bin/env python3
"""Offline comparison of recorded discovery results with independently known truth.

This tool only reads files. It never runs a scanner or contacts an address.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def ipv4(value):
    if not isinstance(value, str):
        raise ValueError("IPv4 addresses must be JSON strings")
    return str(ipaddress.IPv4Address(value))


def read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def host_map(rows, ip_key, alive_key):
    if not isinstance(rows, list) or not rows:
        raise ValueError("Host records must be a nonempty array")
    result = {}
    for row in rows:
        address = ipv4(row[ip_key])
        alive = row[alive_key]
        if type(alive) is not bool:
            raise ValueError(f"{address}: {alive_key} must be a JSON boolean")
        if address in result:
            raise ValueError(f"Duplicate host record: {address}")
        result[address] = alive
    return result


def load_truth(path):
    document = read_json(path)
    if not document.get("Source") or not document.get("ObservedAt"):
        raise ValueError("Ground truth needs Source and ObservedAt; scanner output is not independent truth")
    return document, host_map(document["Hosts"], "IP", "Alive")


def load_report(path):
    document = read_json(path)
    if document.get("Completed") is not True:
        raise ValueError("Partial reports cannot be scored as completed discovery")
    rows = document["Results"]
    observations = host_map(rows, "IP", "IsAlive")
    issues = [r["IP"] for r in rows if r.get("Error") or r.get("Warnings")]
    return observations, {"ProbeErrorIPs": issues, "StartedAt": document.get("StartedAt"), "ExportedAt": document.get("ExportedAt")}


def load_nmap(path, scope_path):
    # The caller supplies the exact recorded IPv4 scope. Nmap may omit silent
    # hosts from XML; missing XML host elements must not silently redefine scope.
    scope_rows = read_json(scope_path)
    if not isinstance(scope_rows, list) or not scope_rows:
        raise ValueError("Nmap scope must be a nonempty JSON array of IPv4 addresses")
    scope = [ipv4(value) for value in scope_rows]
    if len(scope) != len(set(scope)):
        raise ValueError("Nmap scope contains duplicate addresses")
    raw = Path(path).read_bytes()
    if b"<!ENTITY" in raw.upper():
        raise ValueError("XML entity declarations are not accepted")
    root = ET.fromstring(raw)
    finished = root.find("runstats/finished")
    counts = root.find("runstats/hosts")
    if root.tag != "nmaprun" or finished is None or finished.get("exit") != "success":
        raise ValueError("A successfully completed Nmap XML report is required")
    if counts is None or int(counts.get("total", "-1")) != len(scope):
        raise ValueError("Nmap report total does not match its recorded scope")
    observations = dict.fromkeys(scope, False)
    seen = set()
    for host in root.findall("host"):
        addresses = host.findall("address[@addrtype='ipv4']")
        status = host.find("status")
        if len(addresses) != 1 or status is None or status.get("state") not in ("up", "down"):
            raise ValueError("Nmap host has an ambiguous IPv4 address/status")
        address = ipv4(addresses[0].get("addr"))
        if address not in observations or address in seen:
            raise ValueError(f"Nmap host outside recorded scope or duplicate: {address}")
        seen.add(address)
        observations[address] = status.get("state") == "up"
    if int(counts.get("up", "-1")) != sum(observations.values()):
        raise ValueError("Nmap up count and host records disagree")
    return observations, {"ProbeErrorIPs": [], "StartedAtUnix": root.get("start"), "FinishedAtUnix": finished.get("time")}


def evaluate(truth, observations):
    missing = set(truth) - set(observations)
    if missing:
        raise ValueError("Ground-truth addresses absent from recorded scope/results: " + ", ".join(sorted(missing)))
    false_positive = sorted(ip for ip, alive in truth.items() if not alive and observations[ip])
    false_negative = sorted(ip for ip, alive in truth.items() if alive and not observations[ip])
    true_positive = sum(alive and observations[ip] for ip, alive in truth.items())
    true_negative = sum(not alive and not observations[ip] for ip, alive in truth.items())
    detected = true_positive + len(false_positive)
    actually_alive = true_positive + len(false_negative)
    return {
        "ScoredHosts": len(truth), "TruePositive": true_positive, "TrueNegative": true_negative,
        "FalsePositiveIPs": false_positive, "FalseNegativeIPs": false_negative,
        "Precision": true_positive / detected if detected else None,
        "Recall": true_positive / actually_alive if actually_alive else None,
        "UnlabelledIPs": sorted(set(observations) - set(truth)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--truth", required=True, help="Independently verified Hosts/IP/Alive JSON")
    parser.add_argument("--report", action="append", default=[], metavar="LABEL=FILE", help="Completed TKNet or normalized result JSON")
    parser.add_argument("--nmap", metavar="FILE", help="Existing Nmap XML; never executes Nmap")
    parser.add_argument("--nmap-scope", metavar="FILE", help="JSON array of exact IPv4 addresses used for that XML")
    parser.add_argument("--output", help="Write comparison JSON to this file (must not already exist)")
    args = parser.parse_args()
    try:
        if not args.report and not args.nmap:
            raise ValueError("Supply at least one recorded report")
        document, truth = load_truth(args.truth)
        results = {}
        for spec in args.report:
            label, separator, path = spec.partition("=")
            if not separator or not label or label in results:
                raise ValueError("Reports require distinct LABEL=FILE arguments")
            observations, metadata = load_report(path)
            results[label] = {**evaluate(truth, observations), **metadata}
        if args.nmap:
            if not args.nmap_scope or "Nmap" in results:
                raise ValueError("Nmap requires --nmap-scope and a free Nmap label")
            observations, metadata = load_nmap(args.nmap, args.nmap_scope)
            results["Nmap"] = {**evaluate(truth, observations), **metadata}
        output = {
            "GroundTruthSource": document["Source"], "GroundTruthObservedAt": document["ObservedAt"],
            "Scenario": document.get("Scenario"),
            "Interpretation": "Recorded observations only. Unconfirmed is not alive. Missing labels are not offline. Check scope, timing and device state before comparing tools.",
            "Results": results,
        }
        text = json.dumps(output, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "x", encoding="utf-8") as stream:
                stream.write(text + "\n")
        print(text)
    except (ValueError, KeyError, TypeError, AttributeError, OSError, ET.ParseError) as error:
        parser.exit(2, f"Invalid comparison: {error}\n")


if __name__ == "__main__":
    main()

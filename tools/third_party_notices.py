#!/usr/bin/env python3
"""Collect notices from restored dependencies; no network downloads of its own."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def notice_files(directory):
    return sorted(p for p in directory.iterdir() if p.is_file() and
                  any(word in p.name.lower() for word in ("license", "licence", "copying", "notice")))


def generate(go, nuget, runtime_version):
    sections = {}

    def include(label, text):
        sections.setdefault(text.strip(), []).append(label)

    def include_file(label, path):
        include(label + " / " + path.name, path.read_text(encoding="utf-8-sig"))

    modules = set()
    template = "{{if .Module}}{{.Module.Path}}\t{{.Module.Version}}\t{{.Module.Dir}}{{end}}"
    for platform in ("linux", "windows"):
        env = dict(os.environ, GOOS=platform, GOARCH="amd64")
        output = subprocess.check_output([go, "list", "-buildvcs=false", "-deps", "-f", template,
                                          "engine_main.go"], cwd=ROOT, env=env, text=True)
        for line in output.splitlines():
            if line and not line.startswith("tknet\t"):
                modules.add(tuple(line.split("\t", 2)))
    for name, version, directory in sorted(modules):
        files = notice_files(Path(directory))
        if not files:
            raise ValueError("No license notice found for Go module " + name)
        for path in files:
            include_file(name + " " + version, path)
    goroot = Path(subprocess.check_output([go, "env", "GOROOT"], cwd=ROOT, text=True).strip())
    include_file("Go standard library", goroot / "LICENSE")

    assets = json.loads((ROOT / "TKNetUI/obj/project.assets.json").read_text())
    mit_terms = (ROOT / "LICENSE").read_text().split("Permission is hereby granted", 1)[1]
    package_names = []
    for name, library in sorted(assets["libraries"].items()):
        if library["type"] != "package":
            continue
        # These tools are build/debug-only and do not ship in the release package.
        if name.split("/")[0] in {"Avalonia.BuildServices", "AvaloniaUI.DiagnosticsSupport", "Microsoft.NET.ILLink.Tasks"}:
            continue
        directory = nuget / library["path"]
        files = notice_files(directory)
        metadata = ET.parse(next(directory.glob("*.nuspec"))).getroot()
        values = {e.tag.split("}")[-1]: e for e in metadata.iter()}
        license_node = values.get("license")
        if files:
            for path in files:
                include_file(name, path)
        elif name.startswith("Avalonia"):
            include_file(name, ROOT / "docs/licenses/Avalonia.txt")
        elif name.startswith("Tmds.DBus"):
            include_file(name, ROOT / "docs/licenses/Tmds.DBus.txt")
        elif license_node is not None and license_node.text == "MIT":
            copyright_node = values.get("copyright")
            if copyright_node is None or not copyright_node.text:
                raise ValueError("Missing copyright attribution: " + name)
            include(name + " (MIT; attribution from package metadata)",
                    copyright_node.text + "\n\nPermission is hereby granted" + mit_terms)
        else:
            raise ValueError("Review the license for package " + name)
        package_names.append(name)
    include_file("Inter font (SIL Open Font License)", ROOT / "docs/licenses/Inter.txt")
    for platform in ("linux-x64", "win-x64"):
        package = "Microsoft.NETCore.App.Runtime." + platform
        for path in notice_files(nuget / package.lower() / runtime_version):
            include_file(package + "/" + runtime_version, path)

    lines = ["TKNet third-party notices", "=" * 72,
             "TKNet's MIT license does not replace the licenses of its dependencies.",
             "Generated from the Linux/Windows engine imports and restored desktop packages.",
             "Some cross-platform notices cover assets not distributed for a given target.",
             "Refresh this file when changing dependencies or the bundled runtime.", "",
             "Desktop dependency inventory:", *package_names, ""]
    for text, labels in sections.items():
        lines.extend(["=" * 72, "\n".join(labels), "-" * 72, text, ""])
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=os.environ.get("GO_BIN", "go"))
    parser.add_argument("--nuget-root", type=Path, required=True)
    parser.add_argument("--runtime-version", required=True)
    args = parser.parse_args()
    # Build all text before replacing an existing notice bundle on failure.
    output = generate(args.go, args.nuget_root, args.runtime_version)
    (ROOT / "THIRD_PARTY_NOTICES.txt").write_text(output, encoding="utf-8")
    print("Wrote THIRD_PARTY_NOTICES.txt")

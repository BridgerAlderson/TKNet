# Offline Avalonia visual checks

This executable compiles the actual `TKNetUI` AXAML and code-behind into a separate
test assembly, then renders them with Avalonia Headless and Skia. It does not use
an HTML recreation, a desktop session, or a mock control tree. Its `obj` and `bin`
directories are independent of the production application's build.

It generates twenty-two PNGs covering the initial screen, populated SMB and discovery
results, the settings drawer (including its lower options), expanded activity log,
an empty filter result, a collapsed scope panel, unreachable diagnostics, scanning
presentation, inline scope validation, multiple large CIDRs, long share names, incomplete SMB results and confirmed-only discovery
at normal/minimum window sizes. Numeric sorting,
keyboard filter shortcuts and visible/checked counts are also verified. Viewports include 1400 × 900,
1000 × 650, and the application's minimum 900 × 550. All results are synthetic
and use reserved documentation or benchmarking IP addresses. The fixture invokes only the
settings, log and scope toggles, Escape handling, existing local filtering and
scope parsing, wheel input, export/save handlers with in-memory storage, presentation-only updates and the private
`SetScanningState` method. It also changes a fixture scan generation directly
to check that stale queued presentation callbacks are discarded. It does not start the
engine, call a scan handler, open a file manager, read saved credentials, enumerate
network interfaces, or authenticate to any service. `EngineClient.ScanId == 0`
is checked before the window closes. Engine binaries are not embedded in this
test assembly.

Run from the repository root with .NET 10:

```sh
dotnet restore tests/TKNetUI.VisualChecks/TKNetUI.VisualChecks.csproj
dotnet run --project tests/TKNetUI.VisualChecks/TKNetUI.VisualChecks.csproj \
  --no-restore -c Release -- artifacts/ui-preview
```

Offline runs require dependencies to have been restored into your own NuGet cache.
`tools/check.sh` writes previews to the ignored `artifacts/ui-preview/` directory.

`layout-checks.json` records the viewport sizes, positions of important controls,
and assertion count. Checks cover exact image dimensions, control bounds, usable
multiline scope/log heights, password masking, platform restrictions, initial
action availability, settings opening/scrolling/Escape, filter matching/clearing,
the show-all discovery option, preservation of share access details, scan button
states, inline scope error recovery, progress-bar containment, and absence
of an engine start. Populated result views must keep their entire column header
and at least one normal row's height visible, including when the activity log is
expanded at minimum window size. This checks actual grid template and row bounds,
so a positive outer `TabControl` height cannot conceal clipped result content.

Review all PNGs in addition to the assertions: a control being inside the viewport
does not prove that all of its text or template content fits. These checks verify
layout and local UI interactions; they do not claim to test remote SMB access,
Dolphin authentication, native window decoration, or OS-specific font rendering.

The SMB completion fixture feeds the production result/done handlers. It checks
retention of denied/unchecked shares, partial enumeration, Guest warnings, error
filtering, access tooltips and the final completion message without a network.

Export checks hold an isolated file picker open while replacing the scan data.
CSV (all three tabs), discovery JSON, SMB JSON and scope text must retain the
snapshot selected when saving began. The real handlers write to memory streams;
existing contents are truncated, cancellation is harmless, and write failures
are reported. The test does not open a native file picker or write a user file.

Discovery target checks feed the real result/completion handlers, ensuring only
confirmed hosts appear by default while all diagnostics remain accessible. They
exercise the Export menu, completed-scan requirement, TXT/JSON formats, numeric
sorting, deduplication, filter independence, empty results, cancellation and write
failure. Synthetic `alive_ips.txt` / `alive_ips.json` samples in the output folder
contain the bytes written by the real handlers and can be checked offline with
`nmap -sL -n -iL alive_ips.txt` (no DNS resolution or host probes).

The test references the same Avalonia 11.2.1 version as the application. Keep the
Avalonia package versions aligned when upgrading the production project.

## Scrolling regression checks

The same run also writes `scroll-checks.json`. It exercises the real production
grids with 10,000 discovery rows, 1,500 SMB rows and 1,500 unreachable rows at
900 × 550 and 1400 × 900. Checks cover wheel movement in both directions and
axes, bounded realized row counts, first/last result access, a 48-share SMB row
taller than the viewport, incoming results without a scroll reset, and the scope
editor and settings drawer. A hidden tab is laid out before requesting a row.

Activity checks cover preserving both scroll axes and a text selection on append,
following the tail only when already at the bottom, retention-buffer rotation,
multiple messages before a layout, collapsed/reopened activity, and clearing.
Dispatcher checks verify that input runs before a queued presentation burst,
while all current-generation callbacks retain their order and stale callbacks
are discarded. No engine process is started.

Wheel/layout timings are diagnostic samples, not a pass/fail threshold. Headless
Skia rendering does not measure native desktop FPS, GPU/compositor behavior or
physical touchpad inertia.

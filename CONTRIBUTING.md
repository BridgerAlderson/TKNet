# Contributing to TKNet

TKNet ships an Avalonia desktop application with an embedded Go engine. To build
a distributable package, follow the [build instructions](README.md#build-and-run).

Keep changes focused and describe the observable problem, the resulting behavior,
and the checks you ran.

## Build and test

Use the Go version in `go.mod` and a .NET SDK supported by `global.json`.
The Linux test suite also builds the older Fyne UI. On Ubuntu or Debian it needs
`libgl1-mesa-dev`, `xorg-dev`, `libxkbcommon-dev` and `libfontconfig1`.

```sh
go mod download
dotnet restore TKNetUI/TKNetUI.csproj
dotnet restore tests/TKNetUI.Tests/TKNetUI.Tests.csproj
dotnet restore tests/TKNetUI.VisualChecks/TKNetUI.VisualChecks.csproj
bash tools/check.sh
```

The script runs the Go race detector and vet, the desktop logic and layout tests,
and the offline report and packaging tests. The build scripts accept `GO_BIN`
and `DOTNET_BIN` when a toolchain is installed outside the standard search path.
The Windows checks are listed in the [CI workflow](.github/workflows/quality.yml).

For SMB changes, `python3 tools/test_smb_loopback.py` exercises pagination,
partial results and write-check cleanup against a local SMB2 fixture. It
requires Python with Impacket and permission to open a loopback socket.
For Dolphin changes, run the private D-Bus test on Linux.

```sh
dotnet run --project tests/TKNetUI.Tests/TKNetUI.Tests.csproj --no-restore -- --dolphin-dbus
```

With Dolphin installed, `--dolphin-native` additionally tests window startup
and reuse using a temporary local directory.

## Compatibility requirements

- Preserve the JSON line protocol between the UI and the engine. Completion must
  follow every result; cancellation must discard events from the old scan.
- Preserve credential encoding and the Dolphin D-Bus handoff. Credentials must not
  appear in process arguments, logs, copied links, screenshots or issue reports.
- Keep authentication separate from share authorization. A denied share must not
  cause a new authentication attempt with the supplied account.
- Keep discovery observations distinct from confirmed responses. No response is
  not proof that a device is offline.
- Do not replace the existing authentication or discovery behavior as part of a
  visual refactor. Update relevant regression tests when behavior changes.

## UI changes

Use the shared styles in `TKNetUI/Styles/Workspace.axaml`. Run the visual checks at
the default and minimum window sizes, including settings, empty results, long
share names and the expanded activity log. Preview fixtures use documentation
addresses and never start a scan. Keep keyboard focus visible and labels clear.

## Reports and dependencies

Use synthetic or redacted input in reports. Put local exports in `reports/` (ignored
by Git), and check staged files before committing. Do not commit build outputs,
cached engines, personal credentials or backup directories.

Dependency updates should include the relevant build and regression checks. Review
upstream licenses and refresh the third-party notices when redistributing changed
dependencies. Contributions to TKNet are under the [MIT license](LICENSE).

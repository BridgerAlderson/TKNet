# Contributing to TKNet

TKNet ships an Avalonia desktop application with an embedded Go engine. Start with
the build instructions in [README](README.md) and the architecture described there.

Keep changes focused and describe the observable problem, the resulting behavior,
and the checks you ran. Run `bash tools/check.sh` on Linux after restoring the three
.NET projects. Use `./build.sh` or `build.bat` to validate a distributable package.
GitHub Actions also checks the Windows batch build on Windows.

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

#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

GO_BIN="${GO_BIN:-go}"
if [[ -z "${DOTNET_BIN:-}" && -n "${HOME:-}" && -x "$HOME/.dotnet/dotnet" ]] && ! dotnet --version >/dev/null 2>&1; then
    DOTNET_BIN="$HOME/.dotnet/dotnet"
fi
DOTNET_BIN="${DOTNET_BIN:-dotnet}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
for tool in "$GO_BIN" "$DOTNET_BIN" "$PYTHON_BIN"; do
    if ! command -v "$tool" >/dev/null; then
        printf 'Required check tool not found: %s\n' "$tool" >&2
        exit 1
    fi
done
# Restore is an explicit setup step (see README); keep this check reproducible offline.
# Do not race a build that uses the same MSBuild intermediates.
CHECK_LOCK="$PWD/.tknet-build.lock"
if ! mkdir -- "$CHECK_LOCK" 2>/dev/null; then
    printf 'Another build/check may be running. Inspect .tknet-build.lock before retrying.\n' >&2
    exit 1
fi
cleanup() {
    local result=$?
    trap - EXIT
    rmdir -- "$CHECK_LOCK" || printf 'Could not remove check lock: %s\n' "$CHECK_LOCK" >&2
    exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$GO_BIN" test -race -count=1 ./...
"$GO_BIN" vet ./...
"$DOTNET_BIN" run --project tests/TKNetUI.Tests/TKNetUI.Tests.csproj --no-restore
"$DOTNET_BIN" build TKNetUI/TKNetUI.csproj --no-restore -c Release
"$DOTNET_BIN" run --project tests/TKNetUI.VisualChecks/TKNetUI.VisualChecks.csproj --no-restore -c Release -- artifacts/ui-preview
"$PYTHON_BIN" -m unittest discover -s tests/discovery -v
"$PYTHON_BIN" -m unittest discover -s tests/build -v

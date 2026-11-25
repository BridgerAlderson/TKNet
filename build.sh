#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

GO_BIN="${GO_BIN:-go}"
if [[ -z "${DOTNET_BIN:-}" && -n "${HOME:-}" && -x "$HOME/.dotnet/dotnet" ]] && ! dotnet --version >/dev/null 2>&1; then
    DOTNET_BIN="$HOME/.dotnet/dotnet"
fi
DOTNET_BIN="${DOTNET_BIN:-dotnet}"
for tool in "$GO_BIN" "$DOTNET_BIN"; do
    if ! command -v "$tool" >/dev/null; then
        printf 'Required build tool not found: %s\n' "$tool" >&2
        exit 1
    fi
done
if [[ -L release-linux || ( -e release-linux && ! -d release-linux ) ]]; then
    printf 'release-linux must be a regular directory, not a file or symbolic link.\n' >&2
    exit 1
fi

# Both build scripts and the quality checks share this lock because MSBuild obj
# is shared. Never remove another process's lock or its unfinished package.
BUILD_LOCK="$PWD/.tknet-build.lock"
if ! mkdir -- "$BUILD_LOCK" 2>/dev/null; then
    printf 'Another build/check may be running. If it was interrupted, inspect .tknet-build* and remove .tknet-build.lock only after it has stopped.\n' >&2
    exit 1
fi
BUILD_STAGE=''
PUBLISH_INSTALLED=0
cleanup() {
    local result=$?
    trap - EXIT
    if [[ -n "$BUILD_STAGE" ]]; then
        if [[ "$PUBLISH_INSTALLED" == 0 && -d "$BUILD_STAGE/previous" ]]; then
            if [[ ! -e release-linux && ! -L release-linux ]] && mv -T -- "$BUILD_STAGE/previous" release-linux; then
                printf 'Previous release restored.\n' >&2
            else
                printf 'Could not restore automatically. Previous release retained at: %s/previous\n' "$BUILD_STAGE" >&2
                result=1
            fi
        fi
        if [[ "$PUBLISH_INSTALLED" == 1 || ! -e "$BUILD_STAGE/previous" ]]; then
            rm -rf -- "$BUILD_STAGE" || printf 'Build files retained at: %s\n' "$BUILD_STAGE" >&2
        fi
    fi
    rmdir -- "$BUILD_LOCK" || printf 'Could not remove build lock: %s\n' "$BUILD_LOCK" >&2
    exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
BUILD_STAGE="$(mktemp -d "$PWD/.tknet-build.XXXXXX")"
TARGET_ENGINE="$BUILD_STAGE/tknet-engine"

# Compile into the staging directory; never overwrite a previously embedded
# engine if Go or the later desktop publish fails.
printf 'Building Linux x64 engine...\n'
env GOOS=linux GOARCH=amd64 "$GO_BIN" build -trimpath -ldflags='-s -w' -o "$TARGET_ENGINE" engine_main.go
if [[ ! -s "$TARGET_ENGINE" || ! -x "$TARGET_ENGINE" ]]; then
    printf 'Go did not produce a non-empty executable engine.\n' >&2
    exit 1
fi

# The project embeds only this newly built engine and includes the current logo.
printf 'Publishing Linux x64 desktop app...\n'
"$DOTNET_BIN" publish TKNetUI/TKNetUI.csproj -c Release -r linux-x64 --self-contained true \
    -p:PublishSingleFile=true "-p:TkNetEnginePath=$TARGET_ENGINE" -o "$BUILD_STAGE/publish"
for file in TKNetUI libSkiaSharp.so libHarfBuzzSharp.so; do
    if [[ ! -s "$BUILD_STAGE/publish/$file" ]]; then
        printf 'Publish output is missing or empty: %s\n' "$file" >&2
        exit 1
    fi
done
if [[ ! -x "$BUILD_STAGE/publish/TKNetUI" ]]; then
    printf 'Published TKNetUI is not executable.\n' >&2
    exit 1
fi

# Directory renames keep the old complete package available for rollback.
if [[ -e release-linux ]]; then mv -T -- release-linux "$BUILD_STAGE/previous"; fi
mv -T -- "$BUILD_STAGE/publish" release-linux
PUBLISH_INSTALLED=1
printf 'Build complete: release-linux/TKNetUI\n'
printf 'Distribute the entire release-linux folder, including its native libraries.\n'
printf 'Linux still requires desktop system libraries, ping and iproute2; ARP also needs arping and appropriate OS permissions.\n'

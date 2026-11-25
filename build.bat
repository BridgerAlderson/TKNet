@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "STAGE_CREATED="
set "LOCK_HELD="
set "BUILD_STAGE="
pushd "%~dp0" || exit /b 1
if not defined GO_BIN set "GO_BIN=go"
if not defined DOTNET_BIN set "DOTNET_BIN=dotnet"
where "%GO_BIN%" >nul 2>nul
if errorlevel 1 goto missing_go
where "%DOTNET_BIN%" >nul 2>nul
if errorlevel 1 goto missing_dotnet
if exist release if not exist release\ goto invalid_release

rem Share a lock with build.sh and tools/check.sh; obj files must not race.
set "BUILD_LOCK=.tknet-build.lock"
mkdir "%BUILD_LOCK%" 2>nul
if errorlevel 1 goto locked
set "LOCK_HELD=1"
set "GOOS=windows"
set "GOARCH=amd64"
set "BUILD_STAGE=.tknet-build-%RANDOM%-%RANDOM%"
if exist "%BUILD_STAGE%" goto fail
mkdir "%BUILD_STAGE%" || goto fail
set "STAGE_CREATED=1"
set "TARGET_ENGINE=%CD%\%BUILD_STAGE%\tknet-engine.exe"

rem Keep new binaries isolated until the entire package has been validated.
echo Building Windows x64 engine...
"%GO_BIN%" build -trimpath -ldflags="-s -w -H=windowsgui" -o "%TARGET_ENGINE%" engine_main.go
if errorlevel 1 goto fail
if not exist "%TARGET_ENGINE%" goto missing_engine
for %%F in ("%TARGET_ENGINE%") do if %%~zF EQU 0 goto missing_engine

echo Publishing Windows x64 desktop app...
"%DOTNET_BIN%" publish TKNetUI\TKNetUI.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true "-p:TkNetEnginePath=%TARGET_ENGINE%" -o "%BUILD_STAGE%\publish"
if errorlevel 1 goto fail
for %%F in (TKNetUI.exe libSkiaSharp.dll libHarfBuzzSharp.dll av_libglesv2.dll) do (
    if not exist "%BUILD_STAGE%\publish\%%F" goto incomplete_publish
    for %%G in ("%BUILD_STAGE%\publish\%%F") do if %%~zG EQU 0 goto incomplete_publish
)

if exist release (
    move release "%BUILD_STAGE%\previous" >nul
    if errorlevel 1 goto fail
)
move "%BUILD_STAGE%\publish" release >nul
if errorlevel 1 goto fail
rmdir /s /q "%BUILD_STAGE%"
if exist "%BUILD_STAGE%" echo Cleanup incomplete. Build files retained in %BUILD_STAGE%
rmdir "%BUILD_LOCK%"
if errorlevel 1 echo Could not remove %BUILD_LOCK%. Check it before the next build.
echo Build complete: release\TKNetUI.exe
echo Distribute the entire release folder, including its native libraries.
popd
exit /b 0

:missing_go
echo Required build tool not found: "%GO_BIN%"
goto fail
:missing_dotnet
echo Required build tool not found: "%DOTNET_BIN%"
goto fail
:invalid_release
echo The release path must be a directory.
goto fail
:locked
echo Another build/check may be running. If it was interrupted, inspect .tknet-build* and remove .tknet-build.lock only after it has stopped.
goto fail
:missing_engine
echo Go did not produce a non-empty engine.
goto fail
:incomplete_publish
echo Publish output is incomplete. The executable and all required native libraries must exist and be non-empty.
goto fail

:fail
if defined STAGE_CREATED (
    if not exist release if exist "%BUILD_STAGE%\previous" move "%BUILD_STAGE%\previous" release >nul
    if exist "%BUILD_STAGE%\previous" (
        echo Previous release retained in %BUILD_STAGE%\previous
    ) else (
        if exist "%BUILD_STAGE%" rmdir /s /q "%BUILD_STAGE%"
    )
)
if defined LOCK_HELD rmdir "%BUILD_LOCK%"
echo Build failed. The previous release has been retained when available.
popd
exit /b 1

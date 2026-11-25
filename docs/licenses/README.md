# Upstream license sources

These texts are preserved verbatim (with normalized line endings) for attribution:

- [Avalonia at the 11.2.1 package commit](https://github.com/AvaloniaUI/Avalonia/blob/e0438ac2fe67479bf966c7498ba7a82413a5b376/licence.md)
- [Tmds.DBus at the 0.21.3 package commit](https://github.com/tmds/Tmds.DBus/blob/8cb04f66c330b64244e996ff68f685f27f7381a0/COPYING)
- [Inter's SIL Open Font License](https://github.com/rsms/inter/blob/v4.0/LICENSE.txt)

`THIRD_PARTY_NOTICES.txt` also collects the restored Go module, NuGet native
library and .NET runtime notices. The release project copies the complete bundle
and TKNet's own MIT license into each published directory.

To refresh after a dependency update, restore the desktop project and both runtime
packs (`dotnet restore TKNetUI/TKNetUI.csproj -r linux-x64`, then `-r win-x64`),
download the Go dependencies, and run:

```sh
python3 tools/third_party_notices.py --nuget-root /path/to/nuget/packages --runtime-version 8.0.31
```

Use the runtime version actually selected by your SDK. Review the regenerated
notices and any upstream license changes before distributing the package. The
legacy Fyne UI is source-only in this distribution and is not bundled into the
published Avalonia application.

# Release verification

This record covers the packages tested on November 25, 2026 and the first public source commit, `352103e`. The archived manifest contains the sizes and SHA-256 checksums of those initial binaries. [Initial package manifest](quality/package-manifest.json)

## SMB enumeration

A local SMB2 fixture exposed eight disk shares to the same account. The test compared three scanner versions against identical share names and permissions. The server returned the list in one page, then in three pages. The counts exclude the special `IPC$` name.

| Server response | v1.0 | v1.1 | First public commit |
| --- | ---: | ---: | ---: |
| One page | 8 of 8 | 8 of 8 | 8 of 8 |
| Three pages | 2 of 8 | 2 of 8 | 8 of 8 |

The public version requested both continuation pages. In a larger loopback fixture it recovered all 134 expected resources across four pages in each of three runs. When the server denied the second page, the scanner retained the 39 names from the first page and marked the host `Partial`. [SMB2 fixture](../tools/test_smb_loopback.py)

A separate simulation assigned transient TCP failures to different addresses in three runs over 995 synthetic targets. Each run reported the same 911 reachable targets and 2,733 shares. [SMB report fields](SMB_REPORT_REVIEW.md)

## Windows desktop checks

On Windows 11 x64 (build 26200), the packaged desktop application opened, responded, and closed normally. Checks covered local TCP discovery through the embedded engine, eight synthetic SMB scenarios, and export of confirmed addresses as TXT and JSON. The 751 UI assertions included 70 scrolling checks. Opening a real network share in Explorer was outside the scope of this run.

## First public CI run

On commit `352103e`, the Linux job passed. On Windows, the concurrent engine-cache test hit an access denial while publishing the embedded engine. The Windows job stopped before the desktop packaging step. Results for subsequent commits are recorded in the repository's **Actions** tab. [CI run for the first public commit](https://github.com/BridgerAlderson/TKNet/actions/runs/45675399323)

The cache regression tests now finish one engine installation while a second copy is in progress. They check that the second publisher reuses the verified file, that a damaged entry can be repaired, and that a genuine access failure reaches the caller. On Windows the tests also hold a damaged file open, then release it and verify that a later repair succeeds. [Engine cache tests](../tests/TKNetUI.Tests/Program.cs)
